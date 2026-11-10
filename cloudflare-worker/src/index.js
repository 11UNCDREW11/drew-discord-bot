// DREW — league assistant for Discord, running as a Cloudflare Worker.
// Build step 1: league database, gamertag linking with review, fixture import,
// and agreed game times. Game-report intake arrives in step 2.

const REQUIRED_ROLES = ['commissioner', 'gm', 'captain', 'freeagent', 'player'];
const REQUIRED_CHANNELS = [
  'welcome', 'rules', 'announcements', 'generalchat', 'schedule', 'standings',
  'leaguestats', 'weekly slate', 'transactions', 'gmchat', 'captainschat',
  'gamereports', 'reportreview', 'contactcommissioner'
].map((name) => name.replace(/[^a-z0-9]/g, ''));
const EPHEMERAL = 64;
const normalizeName = (name) => String(name ?? '').toLowerCase().replace(/[^a-z0-9]/g, '');
const normalizeGamertag = (tag) => String(tag ?? '').toLowerCase().replace(/\s+/g, '');
const nowIso = () => new Date().toISOString();

const TIMEZONES = {
  eastern: 'America/New_York',
  central: 'America/Chicago',
  mountain: 'America/Denver',
  arizona: 'America/Phoenix',
  pacific: 'America/Los_Angeles',
  utc: 'UTC'
};

// ---------------------------------------------------------------- basics

function json(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json; charset=utf-8' }
  });
}

function hexToBytes(hex) {
  if (typeof hex !== 'string' || hex.length % 2 !== 0 || !/^[0-9a-f]+$/i.test(hex)) {
    throw new Error('Invalid hex value');
  }
  return Uint8Array.from(hex.match(/.{2}/g), (byte) => Number.parseInt(byte, 16));
}

async function verifyDiscordRequest(request, body, publicKey) {
  const signature = request.headers.get('x-signature-ed25519');
  const timestamp = request.headers.get('x-signature-timestamp');
  const reject = (reason, details = {}) => {
    // Do not log the signature, public key, or request body.
    console.warn('Discord interaction signature rejected.', { reason, ...details });
    return false;
  };
  if (!signature || !timestamp || !publicKey) {
    return reject('Required signature data is missing.', {
      hasSignature: Boolean(signature),
      hasTimestamp: Boolean(timestamp),
      hasPublicKey: Boolean(publicKey),
      publicKeyLength: typeof publicKey === 'string' ? publicKey.length : 0
    });
  }
  const timestampSeconds = Number(timestamp);
  const timestampAgeSeconds = Date.now() / 1000 - timestampSeconds;
  if (!Number.isFinite(timestampSeconds) || Math.abs(timestampAgeSeconds) > 300) {
    return reject('Signature timestamp is invalid or outside the five-minute window.', {
      timestampAgeSeconds: Number.isFinite(timestampAgeSeconds) ? Math.round(timestampAgeSeconds) : null
    });
  }
  try {
    const publicKeyBytes = hexToBytes(publicKey);
    const signatureBytes = hexToBytes(signature);
    if (publicKeyBytes.length !== 32 || signatureBytes.length !== 64) {
      return reject('Signature key or signature has an unexpected length.', {
        publicKeyBytesLength: publicKeyBytes.length,
        signatureBytesLength: signatureBytes.length
      });
    }
    const key = await crypto.subtle.importKey('raw', publicKeyBytes, { name: 'Ed25519' }, false, ['verify']);
    const isValid = await crypto.subtle.verify(
      { name: 'Ed25519' },
      key,
      signatureBytes,
      new TextEncoder().encode(timestamp + body)
    );
    if (!isValid) return reject('Ed25519 signature does not match the configured public key and request body.');
    return true;
  } catch (error) {
    return reject('Signature verification could not run.', {
      errorName: error instanceof Error ? error.name : 'UnknownError',
      errorMessage: error instanceof Error ? error.message : 'Unknown error'
    });
  }
}

// ---------------------------------------------------------------- commands

const PLATFORM_CHOICES = [
  { name: 'Xbox', value: 'Xbox' },
  { name: 'PlayStation', value: 'PlayStation' }
];
const TIMEZONE_CHOICES = Object.keys(TIMEZONES).map((key) => ({
  name: key === 'utc' ? 'UTC' : key[0].toUpperCase() + key.slice(1),
  value: key
}));

const commandDefinitions = [
  {
    type: 1,
    name: 'drew',
    description: 'DREW league assistant',
    options: [
      { type: 1, name: 'help', description: 'Show DREW commands' },
      { type: 1, name: 'setup-check', description: 'Commissioner-only check of league roles and channels' },
      { type: 1, name: 'weekly-slate', description: 'Show the latest post in the weekly slate channel' },
      { type: 1, name: 'schedule', description: 'Show the latest post in the schedule channel' },
      {
        type: 2,
        name: 'gamertag',
        description: 'Link or change your in-game name',
        options: [
          {
            type: 1,
            name: 'set',
            description: 'Link your gamertag or PSN name, or change it (a committee member approves)',
            options: [
              { type: 3, name: 'name', description: 'Exactly as it appears in game', required: true, min_length: 2, max_length: 32 },
              { type: 3, name: 'platform', description: 'Your platform', required: true, choices: PLATFORM_CHOICES }
            ]
          },
          { type: 1, name: 'show', description: 'Show your linked gamertag and any pending request' }
        ]
      },
      { type: 1, name: 'myfixtures', description: "Show your franchise's open fixtures and their IDs" },
      {
        type: 1,
        name: 'report',
        description: 'Winning captain: submit the box-score screenshot for a game',
        options: [
          { type: 3, name: 'fixture', description: 'Fixture ID from /drew myfixtures', required: true, max_length: 40 },
          {
            type: 3, name: 'result', description: 'Your result', required: true,
            choices: [{ name: 'We won', value: 'won' }, { name: 'We lost (correction window only)', value: 'lost' }]
          },
          { type: 11, name: 'screenshot', description: 'The Game Stats screen showing both teams', required: true }
        ]
      },
      {
        type: 1,
        name: 'gametime',
        description: 'Propose the agreed start time for a fixture (the other captain confirms)',
        options: [
          { type: 3, name: 'fixture', description: 'Fixture ID from /drew myfixtures', required: true, max_length: 40 },
          { type: 3, name: 'date', description: 'Date, e.g. 2026-11-14', required: true, max_length: 10 },
          { type: 3, name: 'time', description: 'Start time, e.g. 8:30 PM or 20:30', required: true, max_length: 8 },
          { type: 3, name: 'timezone', description: 'Your time zone', required: true, choices: TIMEZONE_CHOICES }
        ]
      },
      {
        type: 2,
        name: 'admin',
        description: 'Commissioner tools',
        options: [
          {
            type: 1,
            name: 'import',
            description: 'Load franchises, players, or fixtures from a CSV file',
            options: [
              {
                type: 3, name: 'kind', description: 'What the file contains', required: true,
                choices: [
                  { name: 'Franchises', value: 'franchises' },
                  { name: 'Players', value: 'players' },
                  { name: 'Fixtures', value: 'fixtures' }
                ]
              },
              { type: 11, name: 'file', description: 'CSV file', required: true }
            ]
          },
          {
            type: 1,
            name: 'readtest',
            description: 'Test how DREW reads a screenshot (nothing is saved)',
            options: [
              { type: 11, name: 'screenshot', description: 'A Game Stats screenshot', required: true },
              {
                type: 3, name: 'model', description: 'Reader model (default: the league setting)', required: false,
                choices: [{ name: 'Haiku 5.5 (cheapest)', value: 'claude-haiku-5-5' }, { name: 'Sonnet 5.5 (stronger)', value: 'claude-sonnet-5-5' }]
              }
            ]
          },
          {
            type: 1,
            name: 'staff',
            description: "Set a franchise's captain and GM",
            options: [
              { type: 3, name: 'franchise', description: 'Franchise ID', required: true, max_length: 40 },
              { type: 6, name: 'captain', description: 'Captain', required: true },
              { type: 6, name: 'gm', description: 'GM (leave empty to keep the current GM)', required: false }
            ]
          },
          {
            type: 1,
            name: 'player',
            description: 'Add a player or update their franchise and position',
            options: [
              { type: 6, name: 'user', description: 'Discord member', required: true },
              { type: 3, name: 'player_id', description: 'League Player ID', required: true, max_length: 40 },
              { type: 3, name: 'name', description: 'Display name', required: true, max_length: 60 },
              { type: 3, name: 'franchise', description: 'Franchise ID (leave empty for free agent)', required: false, max_length: 40 },
              { type: 3, name: 'position', description: 'Declared position this season', required: false, max_length: 20 }
            ]
          }
        ]
      }
    ]
  }
];

async function registerCommands(env) {
  if (!env.DISCORD_BOT_TOKEN || !env.DISCORD_APPLICATION_ID || !env.DISCORD_GUILD_ID) {
    console.error('Command registration skipped: required Discord settings are missing.');
    return;
  }
  const url = `https://discord.com/api/v10/applications/${env.DISCORD_APPLICATION_ID}/guilds/${env.DISCORD_GUILD_ID}/commands`;
  const response = await fetch(url, {
    method: 'PUT',
    headers: {
      authorization: `Bot ${env.DISCORD_BOT_TOKEN}`,
      'content-type': 'application/json'
    },
    body: JSON.stringify(commandDefinitions)
  });
  if (!response.ok) {
    console.error(`Command registration failed with HTTP ${response.status}.`);
  } else {
    console.log('DREW slash commands registered for the configured league server.');
  }
}

// ---------------------------------------------------------------- Discord helpers

function ephemeral(content) {
  return json({ type: 4, data: { content, flags: EPHEMERAL, allowed_mentions: { parse: [] } } });
}

async function discordApi(method, path, token, body) {
  const response = await fetch(`https://discord.com/api/v10${path}`, {
    method,
    headers: { authorization: `Bot ${token}`, ...(body ? { 'content-type': 'application/json' } : {}) },
    body: body ? JSON.stringify(body) : undefined
  });
  if (!response.ok) throw new Error(`Discord API ${method} ${path.split('/')[1]} returned HTTP ${response.status}`);
  return response.status === 204 ? null : response.json();
}

const discordGet = (path, token) => discordApi('GET', path, token);

async function findChannel(env, channelName) {
  const channels = await discordGet(`/guilds/${env.DISCORD_GUILD_ID}/channels`, env.DISCORD_BOT_TOKEN);
  return channels.find((c) => [0, 5].includes(c.type) && normalizeName(c.name) === normalizeName(channelName)) ?? null;
}

async function postToChannel(env, channelName, message) {
  const channel = await findChannel(env, channelName);
  if (!channel) throw new Error(`#${channelName} was not found`);
  const posted = await discordApi('POST', `/channels/${channel.id}/messages`, env.DISCORD_BOT_TOKEN, message);
  return { channelId: channel.id, messageId: posted.id };
}

async function editOriginal(interaction, data) {
  const url = `https://discord.com/api/v10/webhooks/${interaction.application_id}/${interaction.token}/messages/@original`;
  const response = await fetch(url, {
    method: 'PATCH',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ allowed_mentions: { parse: [] }, ...data })
  });
  if (!response.ok) console.error(`Reply could not be delivered; Discord returned HTTP ${response.status}.`);
}

async function followUp(interaction, content) {
  const url = `https://discord.com/api/v10/webhooks/${interaction.application_id}/${interaction.token}`;
  await fetch(url, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ content, flags: EPHEMERAL, allowed_mentions: { parse: [] } })
  });
}

// Reply "thinking…" privately now, then replace it with the result.
function deferEphemeral(ctx, interaction, work) {
  ctx.waitUntil((async () => {
    let content;
    try {
      content = await work();
    } catch (error) {
      console.error(`Command failed: ${error.message}`);
      content = 'Something went wrong on DREW\'s side. Nothing was changed unless a message above says so. Try again, or contact the Commissioner.';
    }
    await editOriginal(interaction, { content });
  })());
  return json({ type: 5, data: { flags: EPHEMERAL } });
}

// Acknowledge a button press now; the work edits the message or sends a private follow-up.
function deferButton(ctx, interaction, work) {
  ctx.waitUntil((async () => {
    try {
      await work();
    } catch (error) {
      console.error(`Button failed: ${error.message}`);
      await followUp(interaction, 'Something went wrong on DREW\'s side. Try again, or contact the Commissioner.');
    }
  })());
  return json({ type: 6 });
}

const invokerId = (interaction) => interaction.member?.user?.id ?? interaction.user?.id;

async function memberRoleNames(interaction, env) {
  const roles = await discordGet(`/guilds/${env.DISCORD_GUILD_ID}/roles`, env.DISCORD_BOT_TOKEN);
  const mine = new Set(interaction.member?.roles ?? []);
  return new Set(roles.filter((r) => mine.has(r.id)).map((r) => normalizeName(r.name)));
}
const isCommissioner = (roles) => roles.has('commissioner');
const isReviewer = (roles) => roles.has('commissioner') || roles.has('committee') || roles.has('leaguecommittee');

// Read /drew <sub> or /drew <group> <sub> and its option values.
function readCommand(interaction) {
  const top = interaction.data?.options?.[0];
  if (!top) return { path: [], opts: {} };
  const leaf = top.type === 2 ? top.options?.[0] : top;
  const path = top.type === 2 ? [top.name, leaf?.name] : [top.name];
  const opts = {};
  for (const option of leaf?.options ?? []) opts[option.name] = option.value;
  return { path, opts };
}

const unix = (iso) => Math.floor(new Date(iso).getTime() / 1000);
const when = (iso) => `<t:${unix(iso)}:F> (<t:${unix(iso)}:R>)`;

// ---------------------------------------------------------------- database helpers

function requireDb(env) {
  if (!env.DB) throw new Error('The DB database binding is missing');
  return env.DB;
}

function audit(db, actor, table, recordId, field, oldValue, newValue, reason) {
  return db.prepare(
    'INSERT INTO audit_log (at, actor, table_name, record_id, field, old_value, new_value, reason) VALUES (?, ?, ?, ?, ?, ?, ?, ?)'
  ).bind(nowIso(), actor, table, String(recordId), field, oldValue == null ? null : String(oldValue),
    newValue == null ? null : String(newValue), reason ?? null);
}

async function franchiseOf(db, franchiseId) {
  return db.prepare('SELECT * FROM franchises WHERE franchise_id = ?').bind(franchiseId).first();
}

// Franchises the member can act for as captain or GM.
async function staffFranchises(db, discordId) {
  const result = await db.prepare(
    'SELECT * FROM franchises WHERE captain_discord_id = ? OR gm_discord_id = ?'
  ).bind(discordId, discordId).all();
  return result.results ?? [];
}

const staffMentions = (franchise) => [...new Set([franchise?.captain_discord_id, franchise?.gm_discord_id].filter(Boolean))];

// ---------------------------------------------------------------- time handling

function zoneOffsetMinutes(utcMs, timeZone) {
  const parts = Object.fromEntries(new Intl.DateTimeFormat('en-US', {
    timeZone, hourCycle: 'h23', year: 'numeric', month: '2-digit', day: '2-digit',
    hour: '2-digit', minute: '2-digit', second: '2-digit'
  }).formatToParts(new Date(utcMs)).map((p) => [p.type, p.value]));
  const asUtc = Date.UTC(Number(parts.year), Number(parts.month) - 1, Number(parts.day),
    Number(parts.hour), Number(parts.minute), Number(parts.second));
  return (asUtc - utcMs) / 60000;
}

// Turn a local date and time in a named zone into a UTC ISO string, or null.
function localToUtc(dateText, timeText, zoneKey) {
  const timeZone = TIMEZONES[zoneKey];
  const d = /^(\d{4})-(\d{1,2})-(\d{1,2})$/.exec(String(dateText).trim());
  const t = /^(\d{1,2})(?::(\d{2}))?\s*([ap]\.?m\.?)?$/i.exec(String(timeText).trim());
  if (!timeZone || !d || !t) return null;
  const [year, month, day] = [Number(d[1]), Number(d[2]), Number(d[3])];
  let hour = Number(t[1]);
  const minute = Number(t[2] ?? 0);
  const meridiem = t[3]?.toLowerCase().replace(/\./g, '');
  if (meridiem) {
    if (hour < 1 || hour > 12) return null;
    if (meridiem === 'pm' && hour !== 12) hour += 12;
    if (meridiem === 'am' && hour === 12) hour = 0;
  }
  if (month < 1 || month > 12 || day < 1 || day > 31 || hour > 23 || minute > 59) return null;
  const localMs = Date.UTC(year, month - 1, day, hour, minute);
  const check = new Date(localMs);
  if (check.getUTCDate() !== day || check.getUTCMonth() !== month - 1) return null;
  let utcMs = localMs - zoneOffsetMinutes(localMs, timeZone) * 60000;
  utcMs = localMs - zoneOffsetMinutes(utcMs, timeZone) * 60000;
  return new Date(utcMs).toISOString();
}

// ---------------------------------------------------------------- CSV

function parseCsv(text) {
  const rows = [];
  let row = [];
  let field = '';
  let quoted = false;
  const input = String(text).replace(/^﻿/, '');
  for (let i = 0; i < input.length; i += 1) {
    const ch = input[i];
    if (quoted) {
      if (ch === '"' && input[i + 1] === '"') { field += '"'; i += 1; }
      else if (ch === '"') quoted = false;
      else field += ch;
    } else if (ch === '"') quoted = true;
    else if (ch === ',') { row.push(field); field = ''; }
    else if (ch === '\n' || ch === '\r') {
      if (ch === '\r' && input[i + 1] === '\n') i += 1;
      row.push(field); field = '';
      if (row.some((cell) => cell.trim() !== '')) rows.push(row);
      row = [];
    } else field += ch;
  }
  row.push(field);
  if (row.some((cell) => cell.trim() !== '')) rows.push(row);
  if (!rows.length) return { header: [], records: [] };
  const header = rows[0].map((h) => h.trim().toLowerCase());
  const records = rows.slice(1).map((cells, index) => {
    const record = { _line: index + 2 };
    header.forEach((h, i) => { record[h] = (cells[i] ?? '').trim(); });
    return record;
  });
  return { header, records };
}

const IMPORT_COLUMNS = {
  franchises: ['franchise_id', 'name', 'crew_name'],
  players: ['player_id', 'display_name', 'franchise_id', 'position'],
  fixtures: ['fixture_id', 'season', 'week', 'home_franchise_id', 'away_franchise_id']
};

// ---------------------------------------------------------------- gamertags

async function gamertagSet(interaction, env, opts) {
  const db = requireDb(env);
  const me = invokerId(interaction);
  const name = String(opts.name ?? '').trim();
  const platform = String(opts.platform ?? '');
  const norm = normalizeGamertag(name);
  if (norm.length < 2) return 'That name is too short. Enter it exactly as it appears in game.';

  const takenBy = await db.prepare(
    "SELECT discord_id FROM gamertags WHERE gamertag_norm = ? AND status IN ('Approved', 'Retired') AND discord_id <> ? LIMIT 1"
  ).bind(norm, me).first();
  if (takenBy) return `**${name}** is already linked to another member. If that's wrong, contact the Commissioner.`;

  const current = await db.prepare(
    "SELECT * FROM gamertags WHERE discord_id = ? AND status = 'Approved' ORDER BY id DESC LIMIT 1"
  ).bind(me).first();
  if (current && current.gamertag_norm === norm && current.platform === platform) {
    return `**${current.gamertag}** (${current.platform}) is already your linked name. Nothing changed.`;
  }

  const pending = await db.prepare(
    "SELECT * FROM gamertags WHERE discord_id = ? AND status = 'Pending'"
  ).bind(me).all();
  const now = nowIso();
  const inserted = await db.prepare(
    "INSERT INTO gamertags (discord_id, gamertag, gamertag_norm, platform, status, requested_at) VALUES (?, ?, ?, ?, 'Pending', ?) RETURNING id"
  ).bind(me, name, norm, platform, now).first();
  const requestId = inserted.id;

  const statements = [audit(db, me, 'gamertags', requestId, 'status', null, 'Pending', `Requested ${name} (${platform})`)];
  for (const old of pending.results ?? []) {
    statements.push(db.prepare("UPDATE gamertags SET status = 'Withdrawn', decided_at = ? WHERE id = ?").bind(now, old.id));
    statements.push(audit(db, me, 'gamertags', old.id, 'status', 'Pending', 'Withdrawn', 'Replaced by a newer request'));
  }
  await db.batch(statements);

  const player = await db.prepare('SELECT * FROM players WHERE discord_id = ?').bind(me).first();
  const lines = [
    `**Gamertag ${current ? 'change' : 'link'} request #${requestId}**`,
    `Member: <@${me}>${player ? ` · Player ID ${player.player_id}` : ' · not yet on a league roster'}`,
    `Requested: **${name}** (${platform})`,
    current ? `Current: ${current.gamertag} (${current.platform}) — kept so past screenshots still match` : 'Current: none'
  ];
  try {
    const posted = await postToChannel(env, 'report-review', {
      content: lines.join('\n'),
      allowed_mentions: { parse: [] },
      components: [{
        type: 1,
        components: [
          { type: 2, style: 3, label: 'Approve', custom_id: `gtag:approve:${requestId}` },
          { type: 2, style: 4, label: 'Reject', custom_id: `gtag:reject:${requestId}` }
        ]
      }]
    });
    await db.prepare('UPDATE gamertags SET review_channel_id = ?, review_message_id = ? WHERE id = ?')
      .bind(posted.channelId, posted.messageId, requestId).run();
  } catch (error) {
    console.error(`Gamertag review post failed: ${error.message}`);
    return `Your request for **${name}** was saved (#${requestId}), but DREW couldn't post it for review. Let the Commissioner know.`;
  }
  return current
    ? `Change request sent: **${name}** (${platform}). **${current.gamertag}** stays active until a committee member approves it.`
    : `Link request sent: **${name}** (${platform}). A committee member will review it.`;
}

async function gamertagShow(interaction, env) {
  const db = requireDb(env);
  const rows = (await db.prepare(
    "SELECT * FROM gamertags WHERE discord_id = ? AND status IN ('Approved', 'Pending', 'Retired') ORDER BY id DESC"
  ).bind(invokerId(interaction)).all()).results ?? [];
  if (!rows.length) return 'You have no linked gamertag yet. Use `/drew gamertag set`.';
  const approved = rows.find((r) => r.status === 'Approved');
  const pending = rows.find((r) => r.status === 'Pending');
  const retired = rows.filter((r) => r.status === 'Retired');
  return [
    approved ? `Linked: **${approved.gamertag}** (${approved.platform})` : 'Linked: none yet',
    pending ? `Pending review: **${pending.gamertag}** (${pending.platform})` : null,
    retired.length ? `Previous names still recognized: ${retired.map((r) => r.gamertag).join(', ')}` : null
  ].filter(Boolean).join('\n');
}

async function gamertagDecide(interaction, env, decision, requestId) {
  const db = requireDb(env);
  const me = invokerId(interaction);
  const roles = await memberRoleNames(interaction, env);
  if (!isReviewer(roles)) {
    await followUp(interaction, 'Only the Commissioner or the League Committee can approve gamertags.');
    return;
  }
  const request = await db.prepare('SELECT * FROM gamertags WHERE id = ?').bind(requestId).first();
  if (!request || request.status !== 'Pending') {
    await editOriginal(interaction, { components: [] });
    await followUp(interaction, `Request #${requestId} was already ${request ? request.status.toLowerCase() : 'removed'}.`);
    return;
  }
  if (request.discord_id === me && !isCommissioner(roles)) {
    await followUp(interaction, 'You can\'t approve your own gamertag. Another reviewer needs to.');
    return;
  }
  const now = nowIso();
  const statements = [];
  if (decision === 'approve') {
    const clash = await db.prepare(
      "SELECT discord_id FROM gamertags WHERE gamertag_norm = ? AND status IN ('Approved', 'Retired') AND discord_id <> ? LIMIT 1"
    ).bind(request.gamertag_norm, request.discord_id).first();
    if (clash) {
      await followUp(interaction, `**${request.gamertag}** is now linked to another member, so it can't be approved. Reject it instead.`);
      return;
    }
    const previous = (await db.prepare(
      "SELECT * FROM gamertags WHERE discord_id = ? AND status = 'Approved'"
    ).bind(request.discord_id).all()).results ?? [];
    for (const old of previous) {
      statements.push(db.prepare("UPDATE gamertags SET status = 'Retired', decided_at = ? WHERE id = ?").bind(now, old.id));
      statements.push(audit(db, me, 'gamertags', old.id, 'status', 'Approved', 'Retired', `Replaced by request #${requestId}`));
    }
  }
  const newStatus = decision === 'approve' ? 'Approved' : 'Rejected';
  statements.push(db.prepare('UPDATE gamertags SET status = ?, decided_by = ?, decided_at = ? WHERE id = ?')
    .bind(newStatus, me, now, requestId));
  statements.push(audit(db, me, 'gamertags', requestId, 'status', 'Pending', newStatus, null));
  await db.batch(statements);

  const original = interaction.message?.content ?? `Gamertag request #${requestId}`;
  await editOriginal(interaction, {
    content: `${original}\n**${newStatus}** by <@${me}> · <t:${unix(now)}:f>`,
    components: []
  });
}

// ---------------------------------------------------------------- fixtures and game times

async function myFixtures(interaction, env) {
  const db = requireDb(env);
  const me = invokerId(interaction);
  let franchiseIds = (await staffFranchises(db, me)).map((f) => f.franchise_id);
  if (!franchiseIds.length) {
    const player = await db.prepare('SELECT franchise_id FROM players WHERE discord_id = ?').bind(me).first();
    if (player?.franchise_id) franchiseIds = [player.franchise_id];
  }
  if (!franchiseIds.length) return 'You aren\'t on a franchise roster or staff yet.';

  const lines = [];
  for (const fid of franchiseIds) {
    const franchise = await franchiseOf(db, fid);
    const rows = (await db.prepare(
      "SELECT * FROM fixtures WHERE (home_id = ? OR away_id = ?) AND status NOT IN ('Final') ORDER BY season, week, fixture_id LIMIT 15"
    ).bind(fid, fid).all()).results ?? [];
    lines.push(`**${franchise?.name ?? fid}** — open fixtures`);
    if (!rows.length) lines.push('None.');
    for (const fx of rows) {
      const home = fx.home_id === fid;
      const opponent = await franchiseOf(db, home ? fx.away_id : fx.home_id);
      const time = fx.agreed_start_utc
        ? `agreed ${when(fx.agreed_start_utc)}`
        : fx.proposed_start_utc ? `proposed ${when(fx.proposed_start_utc)}, awaiting confirmation` : 'no time set';
      lines.push(`\`${fx.fixture_id}\` · Week ${fx.week} · ${home ? 'vs' : '@'} ${opponent?.name ?? '?'} (${home ? 'home' : 'away'}) · ${time}`);
    }
  }
  const text = lines.join('\n');
  return text.length > 1900 ? `${text.slice(0, 1897)}...` : text;
}

async function gameTime(interaction, env, opts) {
  const db = requireDb(env);
  const me = invokerId(interaction);
  const fixtureId = String(opts.fixture ?? '').trim();
  const fx = await db.prepare('SELECT * FROM fixtures WHERE fixture_id = ?').bind(fixtureId).first();
  if (!fx) return `No fixture \`${fixtureId}\`. Check \`/drew myfixtures\` for the IDs.`;
  if (!['Scheduled', 'Time proposed', 'Time set'].includes(fx.status)) {
    return `Fixture \`${fixtureId}\` is already ${fx.status.toLowerCase()}; its time can't be changed here. Contact the Commissioner.`;
  }
  const startUtc = localToUtc(opts.date, opts.time, opts.timezone);
  if (!startUtc) return 'DREW couldn\'t read that date and time. Use a date like `2026-11-14` and a time like `8:30 PM` or `20:30`.';
  const startMs = Date.parse(startUtc);
  if (startMs < Date.now() - 2 * 86400000 || startMs > Date.now() + 45 * 86400000) {
    return 'That time is too far in the past or future. Check the date.';
  }

  const [home, away] = await Promise.all([franchiseOf(db, fx.home_id), franchiseOf(db, fx.away_id)]);
  const mine = new Set((await staffFranchises(db, me)).map((f) => f.franchise_id));
  const roles = await memberRoleNames(interaction, env);
  const side = mine.has(fx.home_id) ? fx.home_id : mine.has(fx.away_id) ? fx.away_id : null;
  if (fx.agreed_start_utc && Date.parse(fx.agreed_start_utc) <= Date.now() && !isCommissioner(roles)) {
    return `The agreed start time for \`${fixtureId}\` has already passed, so only the Commissioner can change it.`;
  }
  const now = nowIso();
  const label = `**${fx.fixture_id}** · Week ${fx.week} · ${home?.name ?? fx.home_id} (home) vs ${away?.name ?? fx.away_id} (away)`;

  if (!side) {
    if (!isCommissioner(roles)) return 'Only the two franchises\' captains or GMs, or the Commissioner, can set this game\'s time.';
    await db.batch([
      db.prepare("UPDATE fixtures SET agreed_start_utc = ?, time_confirmed_by = ?, proposed_start_utc = NULL, proposed_by = NULL, proposed_by_franchise = NULL, status = 'Time set', updated_at = ? WHERE fixture_id = ?")
        .bind(startUtc, me, now, fixtureId),
      audit(db, me, 'fixtures', fixtureId, 'agreed_start_utc', fx.agreed_start_utc, startUtc, 'Set by the Commissioner')
    ]);
    const mentions = [...staffMentions(home), ...staffMentions(away)];
    await postToChannel(env, 'game-reports', {
      content: `${label}\nStart time set by the Commissioner: ${when(startUtc)}\n${mentions.map((id) => `<@${id}>`).join(' ')}`,
      allowed_mentions: { users: mentions }
    });
    return `Start time for \`${fixtureId}\` set to ${when(startUtc)}.`;
  }

  const otherFranchise = side === fx.home_id ? away : home;
  await db.batch([
    db.prepare("UPDATE fixtures SET proposed_start_utc = ?, proposed_by = ?, proposed_by_franchise = ?, agreed_start_utc = NULL, time_confirmed_by = NULL, status = 'Time proposed', updated_at = ? WHERE fixture_id = ?")
      .bind(startUtc, me, side, now, fixtureId),
    audit(db, me, 'fixtures', fixtureId, 'proposed_start_utc', fx.proposed_start_utc ?? fx.agreed_start_utc, startUtc,
      fx.agreed_start_utc ? 'New time proposed; previous agreed time cleared' : 'Time proposed')
  ]);
  const mentions = staffMentions(otherFranchise);
  await postToChannel(env, 'game-reports', {
    content: [
      label,
      `Proposed start: ${when(startUtc)} — by <@${me}>`,
      mentions.length
        ? `${mentions.map((id) => `<@${id}>`).join(' ')} — confirm below, or propose another time with \`/drew gametime\`.`
        : `${otherFranchise?.name ?? 'The other franchise'} has no captain or GM set in DREW yet. Ask the Commissioner.`
    ].join('\n'),
    allowed_mentions: { users: mentions },
    components: [{
      type: 1,
      components: [{ type: 2, style: 3, label: 'Confirm time', custom_id: `gtime:confirm:${fixtureId}:${unix(startUtc)}` }]
    }]
  });
  return `Proposed ${when(startUtc)} for \`${fixtureId}\`. It becomes official when ${otherFranchise?.name ?? 'the other franchise'} confirms.`;
}

async function gameTimeConfirm(interaction, env, fixtureId, proposedUnix) {
  const db = requireDb(env);
  const me = invokerId(interaction);
  const fx = await db.prepare('SELECT * FROM fixtures WHERE fixture_id = ?').bind(fixtureId).first();
  if (!fx || fx.status !== 'Time proposed' || !fx.proposed_start_utc || unix(fx.proposed_start_utc) !== Number(proposedUnix)) {
    await editOriginal(interaction, { components: [] });
    await followUp(interaction, 'This proposal is out of date: a newer time was proposed or the time is already set. Check `/drew myfixtures`.');
    return;
  }
  const mine = new Set((await staffFranchises(db, me)).map((f) => f.franchise_id));
  const otherSide = fx.proposed_by_franchise === fx.home_id ? fx.away_id : fx.home_id;
  if (!mine.has(otherSide)) {
    const roles = await memberRoleNames(interaction, env);
    if (!isCommissioner(roles)) {
      await followUp(interaction, 'Only the other franchise\'s captain or GM (or the Commissioner) can confirm this time.');
      return;
    }
  }
  const now = nowIso();
  await db.batch([
    db.prepare("UPDATE fixtures SET agreed_start_utc = proposed_start_utc, time_confirmed_by = ?, status = 'Time set', updated_at = ? WHERE fixture_id = ?")
      .bind(me, now, fixtureId),
    audit(db, me, 'fixtures', fixtureId, 'agreed_start_utc', null, fx.proposed_start_utc, 'Confirmed by the other franchise')
  ]);
  const original = interaction.message?.content?.split('\n').slice(0, 2).join('\n') ?? `**${fixtureId}**`;
  await editOriginal(interaction, {
    content: `${original}\n**Confirmed** by <@${me}>. Agreed start: ${when(fx.proposed_start_utc)}. The 24-hour report window counts from this time.`,
    components: []
  });
}

// ---------------------------------------------------------------- game reports (step 2)

const STAT_KEYS = ['pts', 'reb', 'ast', 'stl', 'blk', 'fouls', 'tov', 'fgm', 'fga', 'tpm', 'tpa', 'ftm', 'fta'];
// Team totals include team turnovers and team fouls that aren't credited to a player,
// so those two columns are not compared with the player sums.
const SUM_CHECK_KEYS = ['pts', 'reb', 'ast', 'stl', 'blk', 'fgm', 'fga', 'tpm', 'tpa', 'ftm', 'fta'];
const DEFAULT_MODEL = 'claude-haiku-5-5';
const CORRECTION_WINDOW_MS = 48 * 3600000;

const nullableInt = { type: ['integer', 'null'] };
const statProps = Object.fromEntries(STAT_KEYS.map((k) => [k, nullableInt]));
const BOX_SCORE_TOOL = {
  name: 'record_box_score',
  description: 'Record the NBA 2K box score exactly as printed in the screenshot.',
  input_schema: {
    type: 'object',
    properties: {
      readable: { type: 'boolean', description: 'false if this is not a full 2K Game Stats screen or is too unclear to read' },
      problem: { type: 'string', description: 'Why it is unreadable, if readable is false' },
      teams: {
        type: 'array',
        description: 'Both teams, top table first',
        items: {
          type: 'object',
          properties: {
            crew_name: { type: 'string' },
            final_score: nullableInt,
            players: {
              type: 'array',
              items: {
                type: 'object',
                properties: { gamertag: { type: 'string' }, ...statProps },
                required: ['gamertag', ...STAT_KEYS]
              }
            },
            totals: { type: 'object', properties: statProps, required: STAT_KEYS }
          },
          required: ['crew_name', 'final_score', 'players', 'totals']
        }
      }
    },
    required: ['readable', 'teams']
  }
};
const READER_INSTRUCTIONS = [
  'You read NBA 2K MyCAREER "Game Stats" box-score screenshots for a basketball league. Always answer by calling record_box_score exactly once.',
  'Copy every number exactly as printed, even if it looks inconsistent. Never correct, calculate, or guess a value; use null for anything you cannot read clearly.',
  'Copy each gamertag exactly: capitals, digits, spaces, dashes, and underscores. Ignore the platform icon before the name.',
  'List the teams in the order shown, top table first. crew_name is the name in each table header (for example "Agents Of Chaos"). final_score is that team\'s total points.',
  'Columns: PTS, REB, AST, STL, BLK, FOULS (fouls), TO (tov), FGM/FGA (fgm, fga), 3PM/3PA (tpm, tpa), FTM/FTA (ftm, fta). Ignore the GRD column.',
  'totals is the TOTAL row of each table.',
  'If the image is not a full 2K Game Stats screen, is cropped so a team is missing, or is too blurry to read, set readable to false and explain in problem.'
].join('\n');

async function readBoxScore(env, imageUrl, modelOverride) {
  if (!env.ANTHROPIC_API_KEY) return { ok: false, reason: 'setup', detail: 'ANTHROPIC_API_KEY is not set' };
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 25000);
  try {
    const response = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      signal: controller.signal,
      headers: {
        'x-api-key': env.ANTHROPIC_API_KEY,
        'anthropic-version': '2023-06-01',
        'content-type': 'application/json'
      },
      body: JSON.stringify({
        model: modelOverride || env.ANTHROPIC_MODEL || DEFAULT_MODEL,
        max_tokens: 6000,
        system: READER_INSTRUCTIONS,
        tools: [BOX_SCORE_TOOL],
        messages: [{
          role: 'user',
          content: [
            { type: 'image', source: { type: 'url', url: imageUrl } },
            { type: 'text', text: 'Record this box score.' }
          ]
        }]
      })
    });
    if (!response.ok) {
      console.error(`Screenshot reader returned HTTP ${response.status}.`);
      return { ok: false, reason: 'api', detail: `HTTP ${response.status}` };
    }
    const result = await response.json();
    const call = (result.content ?? []).find((block) => block.type === 'tool_use' && block.name === BOX_SCORE_TOOL.name);
    if (!call) return { ok: false, reason: 'api', detail: 'no box score returned' };
    return { ok: true, data: call.input, model: result.model };
  } catch (error) {
    console.error(`Screenshot reader failed: ${error.name}`);
    return { ok: false, reason: error.name === 'AbortError' ? 'timeout' : 'api', detail: error.name };
  } finally {
    clearTimeout(timer);
  }
}

// Gamertag (normalized) -> { player_id, franchise_id, status } for approved and retired names.
async function gamertagLookup(db) {
  const rows = (await db.prepare(
    "SELECT g.gamertag_norm AS norm, g.status AS status, p.player_id AS player_id, p.franchise_id AS franchise_id FROM gamertags g LEFT JOIN players p ON p.discord_id = g.discord_id WHERE g.status IN ('Approved', 'Retired') ORDER BY CASE g.status WHEN 'Approved' THEN 0 ELSE 1 END"
  ).all()).results ?? [];
  const map = new Map();
  for (const row of rows) if (!map.has(row.norm)) map.set(row.norm, row);
  return map;
}

// Pure: compare what was read with the fixture, the claim, and league records.
function runChecks(read, fixture, home, away, claimedWinnerId, lookup) {
  const checks = [];
  const add = (name, ok, detail = '') => checks.push({ name, ok, detail });
  const teams = Array.isArray(read?.teams) ? read.teams : [];
  if (!read?.readable || teams.length !== 2) {
    add('Readable screenshot', false, read?.problem || 'Two teams were not found');
    return { clean: false, checks, sides: null, lines: [], homeScore: null, awayScore: null, winnerId: null };
  }

  // Work out which table is the home team: crew names first, then gamertags.
  const score = (team, franchise) => {
    let s = 0;
    if (franchise?.crew_name && normalizeName(team.crew_name) === normalizeName(franchise.crew_name)) s += 10;
    for (const p of team.players ?? []) if (lookup.get(normalizeGamertag(p.gamertag))?.franchise_id === franchise?.franchise_id) s += 1;
    return s;
  };
  const straight = score(teams[0], home) + score(teams[1], away);
  const swapped = score(teams[0], away) + score(teams[1], home);
  const homeIndex = swapped > straight ? 1 : 0;
  const sides = [homeIndex === 0 ? home : away, homeIndex === 0 ? away : home];
  add('Teams identified', Math.max(straight, swapped) > 0,
    Math.max(straight, swapped) > 0 ? '' : 'Neither the crew names nor any gamertags match this fixture\'s teams');

  const crewProblems = [];
  teams.forEach((team, i) => {
    const franchise = sides[i];
    if (franchise?.crew_name && normalizeName(team.crew_name) !== normalizeName(franchise.crew_name)) {
      crewProblems.push(`"${team.crew_name}" isn't ${franchise.name}'s crew name (${franchise.crew_name})`);
    }
  });
  add('Crew names', crewProblems.length === 0, crewProblems.join('; '));

  const sizeProblems = teams.map((t, i) => ((t.players ?? []).length === 5 ? null : `${sides[i]?.name ?? `Team ${i + 1}`} shows ${(t.players ?? []).length} players`)).filter(Boolean);
  add('Five players per team', sizeProblems.length === 0, sizeProblems.join('; '));

  const blanks = [];
  teams.forEach((t) => {
    for (const p of t.players ?? []) for (const k of STAT_KEYS) if (!Number.isInteger(p[k])) blanks.push(`${p.gamertag} ${k.toUpperCase()}`);
    for (const k of STAT_KEYS) if (!Number.isInteger(t.totals?.[k])) blanks.push(`team total ${k.toUpperCase()}`);
  });
  add('All numbers readable', blanks.length === 0, blanks.slice(0, 6).join(', ') + (blanks.length > 6 ? '…' : ''));

  const pointProblems = [];
  const shotProblems = [];
  teams.forEach((t) => {
    for (const p of t.players ?? []) {
      if ([p.pts, p.fgm, p.tpm, p.ftm].every(Number.isInteger) && p.pts !== 2 * p.fgm + p.tpm + p.ftm) {
        pointProblems.push(`${p.gamertag}: ${p.pts} PTS but 2×${p.fgm} FGM + ${p.tpm} 3PM + ${p.ftm} FTM = ${2 * p.fgm + p.tpm + p.ftm}`);
      }
      const bad = (a, b) => Number.isInteger(a) && Number.isInteger(b) && a > b;
      if (bad(p.fgm, p.fga) || bad(p.tpm, p.tpa) || bad(p.tpm, p.fgm) || bad(p.ftm, p.fta)) shotProblems.push(p.gamertag);
    }
  });
  add('Player points add up', pointProblems.length === 0, pointProblems.slice(0, 3).join('; '));
  add('Made shots never exceed attempts', shotProblems.length === 0, shotProblems.join(', '));

  const sumProblems = [];
  teams.forEach((t, i) => {
    for (const k of SUM_CHECK_KEYS) {
      const sum = (t.players ?? []).reduce((acc, p) => acc + (Number.isInteger(p[k]) ? p[k] : 0), 0);
      if (Number.isInteger(t.totals?.[k]) && sum !== t.totals[k]) sumProblems.push(`${sides[i]?.name ?? `Team ${i + 1}`} ${k.toUpperCase()}: players ${sum}, total ${t.totals[k]}`);
    }
    if (Number.isInteger(t.final_score) && Number.isInteger(t.totals?.pts) && t.final_score !== t.totals.pts) {
      sumProblems.push(`${sides[i]?.name ?? `Team ${i + 1}`} score ${t.final_score} vs total ${t.totals.pts}`);
    }
  });
  add('Team totals match', sumProblems.length === 0, sumProblems.slice(0, 4).join('; '));

  const homeTeam = teams[homeIndex];
  const awayTeam = teams[1 - homeIndex];
  const homeScore = Number.isInteger(homeTeam.totals?.pts) ? homeTeam.totals.pts : homeTeam.final_score;
  const awayScore = Number.isInteger(awayTeam.totals?.pts) ? awayTeam.totals.pts : awayTeam.final_score;
  let winnerId = null;
  if (Number.isInteger(homeScore) && Number.isInteger(awayScore) && homeScore !== awayScore) {
    winnerId = homeScore > awayScore ? home.franchise_id : away.franchise_id;
  }
  add('Winner matches the report', winnerId !== null && winnerId === claimedWinnerId,
    winnerId === null ? 'The score shows no winner' : winnerId === claimedWinnerId ? '' : 'The score shows the other team won');

  const unknown = [];
  const offRoster = [];
  const lines = [];
  teams.forEach((t, i) => {
    for (const p of t.players ?? []) {
      const hit = lookup.get(normalizeGamertag(p.gamertag));
      if (!hit || !hit.player_id) { unknown.push(p.gamertag); continue; }
      if (hit.franchise_id !== sides[i]?.franchise_id) offRoster.push(`${p.gamertag} (not on ${sides[i]?.name})`);
      lines.push({ player_id: hit.player_id, franchise_id: sides[i]?.franchise_id, gamertag: p.gamertag, ...Object.fromEntries(STAT_KEYS.map((k) => [k, p[k]])) });
    }
  });
  add('Every gamertag is linked', unknown.length === 0, unknown.length ? `Not linked: ${unknown.join(', ')}` : '');
  add('Players are on their team\'s roster', offRoster.length === 0, offRoster.join('; '));

  return { clean: checks.every((c) => c.ok), checks, sides: [sides[0]?.franchise_id, sides[1]?.franchise_id], lines, homeScore, awayScore, winnerId };
}

function statTable(read, sides, names) {
  const pad = (s, n) => String(s ?? '-').slice(0, n).padEnd(n);
  const num = (v, n) => String(Number.isInteger(v) ? v : '?').padStart(n);
  const out = [];
  (read?.teams ?? []).forEach((t, i) => {
    out.push(`${pad(names[sides?.[i]] ?? t.crew_name, 16)} PTS REB AST STL BLK TO   FG    3P`);
    for (const p of t.players ?? []) {
      out.push(`${pad(p.gamertag, 16)}${num(p.pts, 4)}${num(p.reb, 4)}${num(p.ast, 4)}${num(p.stl, 4)}${num(p.blk, 4)}${num(p.tov, 3)} ${`${p.fgm ?? '?'}/${p.fga ?? '?'}`.padStart(5)} ${`${p.tpm ?? '?'}/${p.tpa ?? '?'}`.padStart(5)}`);
    }
    if (i === 0) out.push('');
  });
  return `\`\`\`\n${out.join('\n')}\n\`\`\``;
}

function reportCard(fx, home, away, report, outcome, read, statusLine, submitterId) {
  const names = { [home.franchise_id]: home.name, [away.franchise_id]: away.name };
  const scoreLine = Number.isInteger(outcome.homeScore) && Number.isInteger(outcome.awayScore)
    ? `**${home.name}** ${outcome.homeScore} – ${outcome.awayScore} **${away.name}**`
    : `**${home.name}** vs **${away.name}**`;
  return [
    `**Game report #${report.report_id} · ${fx.fixture_id}** · Week ${fx.week} · ${home.name} home`,
    scoreLine,
    `Submitted by <@${submitterId}>`,
    statusLine,
    statTable(read, outcome.sides, names)
  ].join('\n').slice(0, 1990);
}

const checkSummary = (checks) => checks.filter((c) => !c.ok).map((c) => `• ${c.name}${c.detail ? `: ${c.detail}` : ''}`).join('\n');

async function channelIdByName(env, name) {
  return (await findChannel(env, name))?.id ?? null;
}

async function editChannelMessage(env, channelId, messageId, body) {
  if (!channelId || !messageId) return;
  try {
    await discordApi('PATCH', `/channels/${channelId}/messages/${messageId}`, env.DISCORD_BOT_TOKEN, { allowed_mentions: { parse: [] }, ...body });
  } catch (error) {
    console.error(`Could not update a report message: ${error.message}`);
  }
}

async function postReviewItem(env, db, report, fx, reason, details) {
  await db.prepare('INSERT INTO review_queue (fixture_id, kind, reason, opened_at) VALUES (?, ?, ?, ?)')
    .bind(fx.fixture_id, 'game_report', `Report #${report.report_id}: ${reason}`, nowIso()).run();
  await postToChannel(env, 'report-review', {
    content: [
      `**Review needed — game report #${report.report_id} · ${fx.fixture_id}** (${reason})`,
      details,
      'Accept counts it as read. Recheck reruns the checks after a gamertag is linked or a roster is fixed. Reject sends it back for a new screenshot.'
    ].join('\n').slice(0, 1990),
    allowed_mentions: { parse: [] },
    components: [{
      type: 1,
      components: [
        { type: 2, style: 3, label: 'Accept', custom_id: `rv:accept:${report.report_id}` },
        { type: 2, style: 2, label: 'Recheck', custom_id: `rv:recheck:${report.report_id}` },
        { type: 2, style: 4, label: 'Reject', custom_id: `rv:reject:${report.report_id}` }
      ]
    }]
  });
}

async function submitReport(interaction, env, opts) {
  const db = requireDb(env);
  const me = invokerId(interaction);
  const fixtureId = String(opts.fixture ?? '').trim();
  const attachment = interaction.data?.resolved?.attachments?.[opts.screenshot];
  if (!attachment) return 'Attach the box-score screenshot.';
  if (!String(attachment.content_type ?? '').startsWith('image/')) return 'The screenshot must be an image (PNG or JPG).';
  if (attachment.size > 9_000_000) return 'That image is over 9 MB. Send a smaller screenshot.';

  const fx = await db.prepare('SELECT * FROM fixtures WHERE fixture_id = ?').bind(fixtureId).first();
  if (!fx) return `No fixture \`${fixtureId}\`. Check \`/drew myfixtures\`.`;
  const [home, away] = await Promise.all([franchiseOf(db, fx.home_id), franchiseOf(db, fx.away_id)]);
  const mine = new Set((await staffFranchises(db, me)).map((f) => f.franchise_id));
  const side = mine.has(fx.home_id) ? fx.home_id : mine.has(fx.away_id) ? fx.away_id : null;
  if (!side) return 'Only a captain or GM of one of these two franchises can report this game.';

  const inCorrectionWindow = fx.status === 'Unreported' && Date.now() - Date.parse(fx.updated_at) <= CORRECTION_WINDOW_MS;
  if (fx.status === 'Final') return `\`${fixtureId}\` is already final. Contact the Commissioner for a correction.`;
  if (fx.status === 'Reported') return `\`${fixtureId}\` already has a report waiting. The other team can confirm or dispute it on the card in #game-reports.`;
  if (fx.status === 'Unreported' && !inCorrectionWindow) return `The correction window for \`${fixtureId}\` has closed. Contact the Commissioner.`;
  if (opts.result === 'lost' && !inCorrectionWindow) {
    return 'The winning team submits the report. The losing team can only submit during the 48-hour correction window after an Unreported award.';
  }
  const claimedWinnerId = opts.result === 'won' ? side : (side === fx.home_id ? fx.away_id : fx.home_id);

  // Keep the league's own copy of the evidence (Discord links expire).
  let imageKey = null;
  if (env.SCREENSHOTS) {
    try {
      const image = await fetch(attachment.url);
      if (image.ok) {
        imageKey = `reports/${fixtureId}/${Date.now()}-${String(attachment.filename ?? 'screenshot').replace(/[^\w.-]/g, '_')}`;
        await env.SCREENSHOTS.put(imageKey, image.body, { httpMetadata: { contentType: attachment.content_type } });
      }
    } catch (error) {
      console.error(`Screenshot could not be stored: ${error.message}`);
      imageKey = null;
    }
  }

  const read = await readBoxScore(env, attachment.url);
  await audit(db, me, 'fixtures', fixtureId, 'report_attempt', null, read.ok ? 'read' : read.reason,
    `Screenshot ${attachment.filename}${imageKey ? ` stored as ${imageKey}` : ''}`).run();
  if (!read.ok) {
    return read.reason === 'setup'
      ? 'Screenshot reading isn\'t set up yet. Tell the Commissioner. Your report was not submitted.'
      : 'DREW couldn\'t read the screenshot right now. Your report was not submitted — try again in a few minutes. If it keeps failing, contact the Commissioner before the 24-hour deadline.';
  }
  if (!read.data?.readable) {
    return `DREW couldn't read that screenshot${read.data?.problem ? `: ${read.data.problem}` : ''}. Upload a clear, full screenshot of the Game Stats page showing both teams. Your report was not submitted.`;
  }

  const lookup = await gamertagLookup(db);
  const outcome = runChecks(read.data, fx, home, away, claimedWinnerId, lookup);
  const state = outcome.clean ? 'Pending' : 'Needs review';
  const now = nowIso();
  const inserted = await db.prepare(
    'INSERT INTO reports (fixture_id, submitted_by, claimed_result, image_key, raw_read, checks, state, submitted_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?) RETURNING report_id'
  ).bind(fixtureId, me, claimedWinnerId, imageKey, JSON.stringify({ ...read.data, model: read.model }), JSON.stringify(outcome), state, now).first();
  const report = { report_id: inserted.report_id };
  await db.batch([
    db.prepare("UPDATE fixtures SET status = 'Reported', updated_at = ? WHERE fixture_id = ?").bind(now, fixtureId),
    audit(db, me, 'fixtures', fixtureId, 'status', fx.status, 'Reported', `Report #${report.report_id} (${state})`),
    audit(db, me, 'reports', report.report_id, 'state', null, state, outcome.clean ? 'All checks passed' : checkSummary(outcome.checks))
  ]);

  const otherFranchise = side === fx.home_id ? away : home;
  const loserStaff = staffMentions(claimedWinnerId === fx.home_id ? away : home);
  const statusLine = outcome.clean
    ? `Winner: **${claimedWinnerId === fx.home_id ? home.name : away.name}** · ${loserStaff.map((id) => `<@${id}>`).join(' ') || otherFranchise.name}: confirm or dispute within 24 hours. No response means it stands.`
    : `**Needs committee review** — ${outcome.checks.filter((c) => !c.ok).map((c) => c.name).join(', ')}. ${loserStaff.map((id) => `<@${id}>`).join(' ')} you can still confirm or dispute.`;
  const card = await postToChannel(env, 'game-reports', {
    content: reportCard(fx, home, away, report, outcome, read.data, statusLine, me),
    allowed_mentions: { users: loserStaff },
    embeds: [{ title: 'Screenshot as submitted', image: { url: attachment.url } }],
    components: [{
      type: 1,
      components: [
        { type: 2, style: 3, label: 'Confirm', custom_id: `rpt:confirm:${report.report_id}` },
        { type: 2, style: 4, label: 'Dispute', custom_id: `rpt:dispute:${report.report_id}` }
      ]
    }]
  });
  await db.prepare('UPDATE reports SET card_message_id = ? WHERE report_id = ?').bind(card.messageId, report.report_id).run();
  if (!outcome.clean) await postReviewItem(env, db, report, fx, 'checks failed', checkSummary(outcome.checks));

  return outcome.clean
    ? `Report #${report.report_id} submitted and every check passed. It's posted in #game-reports for ${otherFranchise.name} to confirm.`
    : `Report #${report.report_id} submitted, but some checks didn't pass, so the committee will review it:\n${checkSummary(outcome.checks)}`;
}

// Make a report official: write the player lines and close the fixture.
async function finalizeReport(env, db, report, actor, reason) {
  const outcome = JSON.parse(report.checks);
  const fx = await db.prepare('SELECT * FROM fixtures WHERE fixture_id = ?').bind(report.fixture_id).first();
  const now = nowIso();
  const statements = [
    db.prepare('DELETE FROM player_games WHERE fixture_id = ?').bind(report.fixture_id)
  ];
  for (const line of outcome.lines) {
    statements.push(db.prepare(
      'INSERT INTO player_games (fixture_id, player_id, franchise_id, pts, reb, ast, stl, blk, tov, fgm, fga, tpm, tpa, ftm, fta, fouls) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)'
    ).bind(report.fixture_id, line.player_id, line.franchise_id, line.pts, line.reb, line.ast, line.stl, line.blk, line.tov,
      line.fgm, line.fga, line.tpm, line.tpa, line.ftm, line.fta, line.fouls));
  }
  statements.push(db.prepare(
    "UPDATE fixtures SET status = 'Final', result_type = 'Played', winner_id = ?, home_score = ?, away_score = ?, updated_at = ? WHERE fixture_id = ?"
  ).bind(outcome.winnerId, outcome.homeScore, outcome.awayScore, now, report.fixture_id));
  statements.push(db.prepare("UPDATE reports SET state = 'Final', final_at = ? WHERE report_id = ?").bind(now, report.report_id));
  statements.push(audit(db, actor, 'fixtures', report.fixture_id, 'status', fx?.status, 'Final', `Report #${report.report_id}: ${reason}`));
  statements.push(audit(db, actor, 'reports', report.report_id, 'state', report.state, 'Final', reason));
  await db.batch(statements);

  const [home, away] = await Promise.all([franchiseOf(db, fx.home_id), franchiseOf(db, fx.away_id)]);
  const read = JSON.parse(report.raw_read);
  const channelId = await channelIdByName(env, 'game-reports');
  await editChannelMessage(env, channelId, report.card_message_id, {
    content: reportCard(fx, home, away, report, outcome, read,
      `**Final** — ${reason}. Winner: **${outcome.winnerId === fx.home_id ? home.name : away.name}**.`, report.submitted_by),
    components: []
  });
}

async function reportButton(interaction, env, action, reportId) {
  const db = requireDb(env);
  const me = invokerId(interaction);
  const report = await db.prepare('SELECT * FROM reports WHERE report_id = ?').bind(reportId).first();
  if (!report || ['Final', 'Rejected'].includes(report.state)) {
    await followUp(interaction, `Report #${reportId} is already ${report ? report.state.toLowerCase() : 'gone'}.`);
    return;
  }
  const fx = await db.prepare('SELECT * FROM fixtures WHERE fixture_id = ?').bind(report.fixture_id).first();
  const loserId = report.claimed_result === fx.home_id ? fx.away_id : fx.home_id;
  const mine = new Set((await staffFranchises(db, me)).map((f) => f.franchise_id));
  if (!mine.has(loserId)) {
    await followUp(interaction, 'Only the other team\'s captain or GM can confirm or dispute this report.');
    return;
  }
  if (report.opponent_response) {
    await followUp(interaction, `Your team already responded: ${report.opponent_response.split(':')[0]}.`);
    return;
  }
  if (action === 'confirm') {
    await db.batch([
      db.prepare("UPDATE reports SET opponent_response = 'Confirmed' WHERE report_id = ?").bind(reportId),
      audit(db, me, 'reports', reportId, 'opponent_response', null, 'Confirmed', null)
    ]);
    if (report.state === 'Pending') {
      await finalizeReport(env, db, { ...report, opponent_response: 'Confirmed' }, me, 'confirmed by the other team');
    } else {
      await followUp(interaction, 'Confirmation recorded. The committee still needs to review this report before it counts.');
    }
  }
}

function disputeModal(reportId) {
  return json({
    type: 9,
    data: {
      custom_id: `rptmodal:${reportId}`,
      title: `Dispute report #${reportId}`,
      components: [{
        type: 1,
        components: [{ type: 4, custom_id: 'reason', label: 'What is wrong with this report?', style: 2, min_length: 5, max_length: 500, required: true }]
      }]
    }
  });
}

async function disputeSubmit(interaction, env, reportId) {
  const db = requireDb(env);
  const me = invokerId(interaction);
  const reason = String(interaction.data?.components?.[0]?.components?.[0]?.value ?? '').trim();
  const report = await db.prepare('SELECT * FROM reports WHERE report_id = ?').bind(reportId).first();
  if (!report || ['Final', 'Rejected', 'Disputed'].includes(report.state)) {
    await followUp(interaction, `Report #${reportId} is already ${report ? report.state.toLowerCase() : 'gone'}.`);
    return;
  }
  const fx = await db.prepare('SELECT * FROM fixtures WHERE fixture_id = ?').bind(report.fixture_id).first();
  const loserId = report.claimed_result === fx.home_id ? fx.away_id : fx.home_id;
  const mine = new Set((await staffFranchises(db, me)).map((f) => f.franchise_id));
  if (!mine.has(loserId)) {
    await followUp(interaction, 'Only the other team\'s captain or GM can dispute this report.');
    return;
  }
  await db.batch([
    db.prepare("UPDATE reports SET state = 'Disputed', opponent_response = ? WHERE report_id = ?").bind(`Disputed: ${reason}`, reportId),
    audit(db, me, 'reports', reportId, 'state', report.state, 'Disputed', reason)
  ]);
  const outcome = JSON.parse(report.checks);
  const failed = checkSummary(outcome.checks);
  await postReviewItem(env, db, report, fx, 'disputed', `Dispute from <@${me}>: ${reason}${failed ? `\nChecks that also failed:\n${failed}` : '\nAll automatic checks had passed.'}`);
  const original = interaction.message?.content ?? '';
  const lines = original.split('\n');
  if (lines.length > 3) lines[3] = `**Disputed** by <@${me}> — the committee will review it.`;
  await editOriginal(interaction, { content: lines.join('\n'), components: [] });
}

async function reviewButton(interaction, env, action, reportId) {
  const db = requireDb(env);
  const me = invokerId(interaction);
  if (!isReviewer(await memberRoleNames(interaction, env))) {
    await followUp(interaction, 'Only the Commissioner or the League Committee can review reports.');
    return;
  }
  const report = await db.prepare('SELECT * FROM reports WHERE report_id = ?').bind(reportId).first();
  if (!report || ['Final', 'Rejected'].includes(report.state)) {
    await editOriginal(interaction, { components: [] });
    await followUp(interaction, `Report #${reportId} is already ${report ? report.state.toLowerCase() : 'gone'}.`);
    return;
  }
  const fx = await db.prepare('SELECT * FROM fixtures WHERE fixture_id = ?').bind(report.fixture_id).first();
  const [home, away] = await Promise.all([franchiseOf(db, fx.home_id), franchiseOf(db, fx.away_id)]);
  const stamp = (text) => `${interaction.message?.content ?? ''}\n**${text}** by <@${me}> · <t:${unix(nowIso())}:f>`.slice(0, 1990);
  const resolve = (resolution) => db.prepare(
    "UPDATE review_queue SET resolution = ?, assigned_to = ?, resolved_at = ? WHERE resolved_at IS NULL AND reason LIKE ?"
  ).bind(resolution, me, nowIso(), `Report #${reportId}:%`);

  if (action === 'recheck') {
    const read = JSON.parse(report.raw_read);
    const outcome = runChecks(read, fx, home, away, report.claimed_result, await gamertagLookup(db));
    const newState = report.state === 'Disputed' ? 'Disputed' : (outcome.clean ? 'Pending' : 'Needs review');
    await db.batch([
      db.prepare('UPDATE reports SET checks = ?, state = ? WHERE report_id = ?').bind(JSON.stringify(outcome), newState, reportId),
      audit(db, me, 'reports', reportId, 'checks', null, outcome.clean ? 'all passed' : 'some failed', 'Rechecked')
    ]);
    if (outcome.clean && report.opponent_response === 'Confirmed' && newState === 'Pending') {
      await finalizeReport(env, db, { ...report, checks: JSON.stringify(outcome), state: newState }, me, 'rechecked by the committee and confirmed by the other team');
      await resolve('Rechecked; final').run();
      await editOriginal(interaction, { content: stamp('Rechecked: all checks pass, already confirmed, now final'), components: [] });
      return;
    }
    if (outcome.clean && newState === 'Pending') {
      await resolve('Rechecked; all checks pass').run();
      await editOriginal(interaction, { content: stamp('Rechecked: all checks pass. Waiting on the other team or the 24-hour window'), components: [] });
      return;
    }
    await followUp(interaction, outcome.clean ? 'All checks pass now, but this report is disputed, so choose Accept or Reject.' : `Still failing:\n${checkSummary(outcome.checks)}`);
    return;
  }

  if (action === 'accept') {
    const outcome = JSON.parse(report.checks);
    const unlinked = outcome.checks.find((c) => c.name === 'Every gamertag is linked' && !c.ok);
    if (unlinked || !outcome.winnerId || outcome.lines.length === 0) {
      await followUp(interaction, unlinked
        ? `Can't accept yet: ${unlinked.detail}. Have those players link their gamertags (or approve their requests), then press Recheck.`
        : 'Can\'t accept: the screenshot shows no clear winner. Reject it and ask for a new screenshot.');
      return;
    }
    await finalizeReport(env, db, report, me, 'accepted by the committee');
    await resolve('Accepted').run();
    await editOriginal(interaction, { content: stamp('Accepted — now final'), components: [] });
    return;
  }

  if (action === 'reject') {
    const backTo = fx.agreed_start_utc ? 'Time set' : 'Scheduled';
    await db.batch([
      db.prepare("UPDATE reports SET state = 'Rejected' WHERE report_id = ?").bind(reportId),
      db.prepare('UPDATE fixtures SET status = ?, updated_at = ? WHERE fixture_id = ?').bind(backTo, nowIso(), fx.fixture_id),
      audit(db, me, 'reports', reportId, 'state', report.state, 'Rejected', 'Rejected by the committee'),
      audit(db, me, 'fixtures', fx.fixture_id, 'status', fx.status, backTo, `Report #${reportId} rejected`),
      resolve('Rejected')
    ]);
    const channelId = await channelIdByName(env, 'game-reports');
    const submitter = report.submitted_by;
    await editChannelMessage(env, channelId, report.card_message_id, {
      content: `**Game report #${reportId} · ${fx.fixture_id}** — rejected by the committee. <@${submitter}> please submit a new screenshot with \`/drew report\`.`,
      allowed_mentions: { users: [submitter] },
      embeds: [],
      components: []
    });
    await editOriginal(interaction, { content: stamp('Rejected — captain asked to resubmit'), components: [] });
  }
}

// ---------------------------------------------------------------- admin

const LEAGUE_ONLY_CHECKS = new Set(['Teams identified', 'Crew names', 'Winner matches the report', 'Every gamertag is linked', "Players are on their team's roster"]);

async function adminReadTest(interaction, env, opts) {
  const attachment = interaction.data?.resolved?.attachments?.[opts.screenshot];
  if (!attachment || !String(attachment.content_type ?? '').startsWith('image/')) return 'Attach a screenshot image.';
  const started = Date.now();
  const read = await readBoxScore(env, attachment.url, opts.model);
  const seconds = ((Date.now() - started) / 1000).toFixed(1);
  if (!read.ok) return read.reason === 'setup' ? 'ANTHROPIC_API_KEY is not set in Cloudflare.' : `The reader failed (${read.detail}). Try again.`;
  if (!read.data?.readable) return `Unreadable (${seconds}s, ${read.model}): ${read.data?.problem ?? 'no reason given'}`;
  const t = read.data.teams ?? [];
  const a = { franchise_id: 'A', name: t[0]?.crew_name ?? 'Team 1', crew_name: t[0]?.crew_name };
  const b = { franchise_id: 'B', name: t[1]?.crew_name ?? 'Team 2', crew_name: t[1]?.crew_name };
  const winner = (t[0]?.totals?.pts ?? 0) >= (t[1]?.totals?.pts ?? 0) ? 'A' : 'B';
  const outcome = runChecks(read.data, { fixture_id: 'TEST' }, a, b, winner, new Map());
  const checks = outcome.checks.filter((c) => !LEAGUE_ONLY_CHECKS.has(c.name));
  return [
    `**Read test** · ${read.model} · ${seconds}s`,
    `${a.name} ${outcome.homeScore ?? '?'} – ${outcome.awayScore ?? '?'} ${b.name}`,
    ...checks.map((c) => `${c.ok ? '✅' : '❌'} ${c.name}${c.detail ? `: ${c.detail}` : ''}`),
    statTable(read.data, outcome.sides, { A: a.name, B: b.name }),
    'Compare the table with the screenshot. Gamertag, crew, and roster checks are skipped in a test.'
  ].join('\n').slice(0, 1990);
}

async function adminImport(interaction, env, opts) {
  const db = requireDb(env);
  const me = invokerId(interaction);
  const kind = opts.kind;
  const attachment = interaction.data?.resolved?.attachments?.[opts.file];
  if (!IMPORT_COLUMNS[kind]) return 'Choose franchises, players, or fixtures.';
  if (!attachment) return 'Attach the CSV file.';
  if (attachment.size > 200000) return 'That file is too large. Keep imports under 200 KB.';
  const response = await fetch(attachment.url);
  if (!response.ok) return 'DREW couldn\'t download the file. Try uploading it again.';
  const { header, records } = parseCsv(await response.text());
  const missing = IMPORT_COLUMNS[kind].filter((c) => !header.includes(c));
  if (missing.length) return `The file is missing these columns: ${missing.join(', ')}. The first row must be: ${IMPORT_COLUMNS[kind].join(',')}`;
  if (!records.length) return 'The file has no rows after the header.';
  if (records.length > 500) return 'Import up to 500 rows at a time.';

  const now = nowIso();
  const problems = [];
  const statements = [];
  const franchiseIds = new Set(((await db.prepare('SELECT franchise_id FROM franchises').all()).results ?? []).map((f) => f.franchise_id));
  let skipped = 0;

  if (kind === 'franchises') {
    for (const r of records) {
      if (!r.franchise_id || !r.name) { problems.push(`line ${r._line}: franchise_id and name are required`); continue; }
      statements.push(db.prepare(
        'INSERT INTO franchises (franchise_id, name, crew_name, updated_at) VALUES (?, ?, ?, ?) ON CONFLICT(franchise_id) DO UPDATE SET name = excluded.name, crew_name = excluded.crew_name, updated_at = excluded.updated_at'
      ).bind(r.franchise_id, r.name, r.crew_name || null, now));
    }
  } else if (kind === 'players') {
    for (const r of records) {
      if (!r.player_id || !r.display_name) { problems.push(`line ${r._line}: player_id and display_name are required`); continue; }
      if (r.franchise_id && !franchiseIds.has(r.franchise_id)) { problems.push(`line ${r._line}: unknown franchise ${r.franchise_id}`); continue; }
      if (r.discord_id && !/^\d{15,22}$/.test(r.discord_id)) { problems.push(`line ${r._line}: discord_id should be the long number from "Copy User ID"`); continue; }
      statements.push(db.prepare(
        'INSERT INTO players (player_id, display_name, discord_id, franchise_id, position, updated_at) VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(player_id) DO UPDATE SET display_name = excluded.display_name, discord_id = COALESCE(excluded.discord_id, players.discord_id), franchise_id = excluded.franchise_id, position = excluded.position, updated_at = excluded.updated_at'
      ).bind(r.player_id, r.display_name, r.discord_id || null, r.franchise_id || null, r.position || null, now));
    }
  } else {
    const existing = new Map(((await db.prepare('SELECT fixture_id, status FROM fixtures').all()).results ?? []).map((f) => [f.fixture_id, f.status]));
    for (const r of records) {
      const season = Number(r.season);
      const week = Number(r.week);
      if (!r.fixture_id || !Number.isInteger(season) || !Number.isInteger(week)) { problems.push(`line ${r._line}: fixture_id, season, and week are required`); continue; }
      if (!franchiseIds.has(r.home_franchise_id) || !franchiseIds.has(r.away_franchise_id)) { problems.push(`line ${r._line}: unknown franchise`); continue; }
      if (r.home_franchise_id === r.away_franchise_id) { problems.push(`line ${r._line}: a team can't play itself`); continue; }
      if (existing.has(r.fixture_id) && existing.get(r.fixture_id) !== 'Scheduled') { skipped += 1; continue; }
      statements.push(db.prepare(
        "INSERT INTO fixtures (fixture_id, season, week, home_id, away_id, status, updated_at) VALUES (?, ?, ?, ?, ?, 'Scheduled', ?) ON CONFLICT(fixture_id) DO UPDATE SET season = excluded.season, week = excluded.week, home_id = excluded.home_id, away_id = excluded.away_id, updated_at = excluded.updated_at WHERE fixtures.status = 'Scheduled'"
      ).bind(r.fixture_id, season, week, r.home_franchise_id, r.away_franchise_id, now));
    }
  }

  if (problems.length) {
    const shown = problems.slice(0, 12).join('\n');
    return `Nothing was imported. Fix these rows and upload again:\n${shown}${problems.length > 12 ? `\n…and ${problems.length - 12} more` : ''}`;
  }
  statements.push(audit(db, me, kind, 'import', null, null, `${statements.length} rows`, `CSV import: ${attachment.filename}`));
  await db.batch(statements);
  return `Imported ${statements.length - 1} ${kind} row(s) from **${attachment.filename}**.${skipped ? ` Skipped ${skipped} fixture(s) that already have a time or result.` : ''}`;
}

async function adminStaff(interaction, env, opts) {
  const db = requireDb(env);
  const me = invokerId(interaction);
  const franchise = await franchiseOf(db, String(opts.franchise ?? '').trim());
  if (!franchise) return `No franchise \`${opts.franchise}\`. Import franchises first.`;
  const gm = opts.gm ?? franchise.gm_discord_id;
  await db.batch([
    db.prepare('UPDATE franchises SET captain_discord_id = ?, gm_discord_id = ?, updated_at = ? WHERE franchise_id = ?')
      .bind(opts.captain, gm, nowIso(), franchise.franchise_id),
    audit(db, me, 'franchises', franchise.franchise_id, 'captain_discord_id', franchise.captain_discord_id, opts.captain, null),
    audit(db, me, 'franchises', franchise.franchise_id, 'gm_discord_id', franchise.gm_discord_id, gm, null)
  ]);
  return `**${franchise.name}** — captain <@${opts.captain}>${gm ? `, GM <@${gm}>` : ', no GM set'}.`;
}

async function adminPlayer(interaction, env, opts) {
  const db = requireDb(env);
  const me = invokerId(interaction);
  const playerId = String(opts.player_id).trim();
  const franchiseId = opts.franchise ? String(opts.franchise).trim() : null;
  if (franchiseId && !(await franchiseOf(db, franchiseId))) return `No franchise \`${franchiseId}\`.`;
  const clash = await db.prepare('SELECT player_id FROM players WHERE discord_id = ? AND player_id <> ?').bind(opts.user, playerId).first();
  if (clash) return `<@${opts.user}> is already Player ID ${clash.player_id}. Use that ID to update them.`;
  const before = await db.prepare('SELECT * FROM players WHERE player_id = ?').bind(playerId).first();
  await db.batch([
    db.prepare('INSERT INTO players (player_id, display_name, discord_id, franchise_id, position, updated_at) VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(player_id) DO UPDATE SET display_name = excluded.display_name, discord_id = excluded.discord_id, franchise_id = excluded.franchise_id, position = COALESCE(excluded.position, players.position), updated_at = excluded.updated_at')
      .bind(playerId, String(opts.name).trim(), opts.user, franchiseId, opts.position ? String(opts.position).trim() : null, nowIso()),
    audit(db, me, 'players', playerId, 'record', before ? JSON.stringify(before) : null,
      JSON.stringify({ discord_id: opts.user, franchise_id: franchiseId, position: opts.position ?? before?.position ?? null }),
      before ? 'Updated' : 'Added')
  ]);
  return `${before ? 'Updated' : 'Added'} Player ID ${playerId} — <@${opts.user}>, ${franchiseId ?? 'free agent'}${opts.position ? `, ${opts.position}` : ''}.`;
}

async function requireCommissioner(interaction, env) {
  return isCommissioner(await memberRoleNames(interaction, env));
}

// ---------------------------------------------------------------- existing read-only commands

async function runSetupCheck(interaction, env) {
  if (!env.DISCORD_BOT_TOKEN || !env.DISCORD_GUILD_ID) {
    return ephemeral('DREW setup is incomplete. Ask the Commissioner to check the bot configuration.');
  }
  try {
    const [roles, channels] = await Promise.all([
      discordGet(`/guilds/${env.DISCORD_GUILD_ID}/roles`, env.DISCORD_BOT_TOKEN),
      discordGet(`/guilds/${env.DISCORD_GUILD_ID}/channels`, env.DISCORD_BOT_TOKEN)
    ]);
    const commissioner = roles.find((role) => normalizeName(role.name) === 'commissioner');
    const memberRoleIds = interaction.member?.roles ?? [];
    if (!commissioner || !memberRoleIds.includes(commissioner.id)) {
      return ephemeral('This setup check is available to the Commissioner role.');
    }
    const missingRoles = REQUIRED_ROLES.filter((expected) => !roles.some((role) => normalizeName(role.name) === expected));
    const missingChannels = REQUIRED_CHANNELS.filter((expected) =>
      !channels.some((channel) => [0, 5].includes(channel.type) && normalizeName(channel.name) === expected));
    const franchiseCategoryIds = new Set(channels
      .filter((channel) => channel.type === 4
        && normalizeName(channel.name).includes('franchise')
        && normalizeName(channel.name).includes('chat'))
      .map((category) => category.id));
    const franchiseChannelCount = channels.filter((channel) =>
      [0, 5].includes(channel.type) && franchiseCategoryIds.has(channel.parent_id)).length;
    const hasCommittee = roles.some((role) => ['committee', 'leaguecommittee'].includes(normalizeName(role.name)));
    let database = 'Database: not connected (DB binding missing).';
    if (env.DB) {
      try {
        const counts = await env.DB.prepare(
          'SELECT (SELECT COUNT(*) FROM franchises) AS f, (SELECT COUNT(*) FROM players) AS p, (SELECT COUNT(*) FROM fixtures) AS x'
        ).first();
        database = `Database: connected — ${counts.f} franchises, ${counts.p} players, ${counts.x} fixtures.`;
      } catch {
        database = 'Database: connected, but the tables are missing. Run schema.sql in the D1 console.';
      }
    }
    const lines = ['**DREW server setup check**'];
    lines.push(missingRoles.length
      ? `Missing roles: ${missingRoles.map((name) => `\`${name}\``).join(', ')}`
      : `Roles: all ${REQUIRED_ROLES.length} required roles found.`);
    lines.push(hasCommittee ? 'Committee role: found.' : 'Committee role: not found. Create a role named `Committee` so members can approve gamertags.');
    lines.push(missingChannels.length
      ? `Missing text channels: ${missingChannels.map((name) => `\`#${name}\``).join(', ')}`
      : `Text channels: all ${REQUIRED_CHANNELS.length} required channels found.`);
    lines.push(franchiseChannelCount === 8
      ? 'Franchise chats: all 8 text channels found under a Franchise Chats category.'
      : `Franchise chats: found ${franchiseChannelCount} text channels under a Franchise Chats category; expected 8.`);
    lines.push(database);
    return ephemeral(lines.join('\n'));
  } catch (error) {
    console.error(`Setup check could not read server configuration: ${error.message}`);
    return ephemeral('DREW could not complete the setup check. Ask the Commissioner to review its server access and configuration.');
  }
}

async function getLatestChannelPost(env, channelName, heading) {
  if (!env.DISCORD_BOT_TOKEN || !env.DISCORD_GUILD_ID) {
    return 'DREW setup is incomplete. Ask the Commissioner to check the bot configuration.';
  }
  try {
    const channel = await findChannel(env, channelName);
    if (!channel) return `DREW could not find the #${channelName} channel.`;
    const messages = await discordGet(`/channels/${channel.id}/messages?limit=10`, env.DISCORD_BOT_TOKEN);
    const latest = messages.find((message) => message.content?.trim() || message.embeds?.length);
    if (!latest) return `No post with readable text has been found in #${channelName} yet.`;
    const parts = [latest.content?.trim()];
    for (const embed of latest.embeds ?? []) {
      const embedText = [embed.title, embed.description,
        ...(embed.fields ?? []).flatMap((field) => [field.name, field.value])]
        .filter(Boolean).join('\n');
      if (embedText) parts.push(embedText);
    }
    let slate = parts.filter(Boolean).join('\n\n');
    if (!slate) return `The latest post in #${channelName} has no readable text.`;
    if (slate.length > 1750) slate = `${slate.slice(0, 1747)}...`;
    const messageLink = `https://discord.com/channels/${env.DISCORD_GUILD_ID}/${channel.id}/${latest.id}`;
    return `**${heading}**\n${slate}\n\n[Open the post in #${channelName}](${messageLink})`;
  } catch (error) {
    console.error(`#${channelName} could not be read: ${error.message}`);
    return `DREW could not read #${channelName}. Check that the bot can view the channel and read its message history.`;
  }
}

const HELP_TEXT = [
  '**DREW commands**',
  '`/drew gamertag set` — link your in-game name, or change it after a name change. A committee member approves; your old name stays recognized for past games.',
  '`/drew gamertag show` — see your linked name and any pending request.',
  '`/drew myfixtures` — your franchise\'s open fixtures, their IDs, and agreed times.',
  '`/drew gametime` — captains/GMs propose a game\'s start time; the other franchise confirms. The 24-hour report window counts from the agreed time.',
  '`/drew report` — winning captain/GM attaches the Game Stats screenshot within 24 hours. DREW reads the stats, checks them, and posts a card; the other team can Confirm or Dispute.',
  '`/drew weekly-slate`, `/drew schedule` — latest posts from those channels.',
  'Commissioner: `/drew setup-check`, `/drew admin import`, `/drew admin staff`, `/drew admin player`, `/drew admin readtest`.'
].join('\n');

// ---------------------------------------------------------------- router

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    if (request.method === 'GET' && url.pathname === '/health') {
      return new Response('DREW endpoint is ready.', { headers: { 'content-type': 'text/plain; charset=utf-8' } });
    }
    if (request.method !== 'POST' || url.pathname !== '/interactions') {
      return new Response('Not found.', { status: 404 });
    }

    const body = await request.text();
    if (!(await verifyDiscordRequest(request, body, env.DISCORD_PUBLIC_KEY))) {
      return new Response('Invalid request signature.', { status: 401 });
    }

    let interaction;
    try {
      interaction = JSON.parse(body);
    } catch {
      return new Response('Invalid JSON.', { status: 400 });
    }

    if (interaction.type === 1) {
      // Discord validates an interaction endpoint with a signed PING. Registering
      // commands here avoids requiring a separate local command-publishing step.
      ctx.waitUntil(registerCommands(env));
      return json({ type: 1 });
    }

    // Buttons
    if (interaction.type === 3) {
      const [scope, action, ...rest] = String(interaction.data?.custom_id ?? '').split(':');
      if (scope === 'gtag' && ['approve', 'reject'].includes(action)) {
        return deferButton(ctx, interaction, () => gamertagDecide(interaction, env, action, Number(rest[0])));
      }
      if (scope === 'gtime' && action === 'confirm') {
        const proposedUnix = rest.pop();
        return deferButton(ctx, interaction, () => gameTimeConfirm(interaction, env, rest.join(':'), proposedUnix));
      }
      if (scope === 'rpt' && action === 'dispute') return disputeModal(Number(rest[0]));
      if (scope === 'rpt' && action === 'confirm') {
        return deferButton(ctx, interaction, () => reportButton(interaction, env, 'confirm', Number(rest[0])));
      }
      if (scope === 'rv' && ['accept', 'recheck', 'reject'].includes(action)) {
        return deferButton(ctx, interaction, () => reviewButton(interaction, env, action, Number(rest[0])));
      }
      return ephemeral('This button is no longer active.');
    }

    // Dispute form submitted
    if (interaction.type === 5) {
      const [scope, reportId] = String(interaction.data?.custom_id ?? '').split(':');
      if (scope === 'rptmodal') return deferButton(ctx, interaction, () => disputeSubmit(interaction, env, Number(reportId)));
      return ephemeral('This form is no longer active.');
    }

    if (interaction.type !== 2 || interaction.data?.name !== 'drew') {
      return ephemeral('DREW does not recognize that command.');
    }

    const { path, opts } = readCommand(interaction);
    const command = path.join(' ');

    if (command === 'help') {
      // Refresh the guild command list after a deployment adds or changes commands.
      ctx.waitUntil(registerCommands(env));
      return ephemeral(HELP_TEXT);
    }
    if (command === 'setup-check') return runSetupCheck(interaction, env);
    if (command === 'weekly-slate' || command === 'schedule') {
      const heading = command === 'weekly-slate' ? 'Current weekly slate' : 'Current schedule';
      return deferEphemeral(ctx, interaction, () => getLatestChannelPost(env, command, heading));
    }
    if (command === 'gamertag set') return deferEphemeral(ctx, interaction, () => gamertagSet(interaction, env, opts));
    if (command === 'gamertag show') return deferEphemeral(ctx, interaction, () => gamertagShow(interaction, env));
    if (command === 'myfixtures') return deferEphemeral(ctx, interaction, () => myFixtures(interaction, env));
    if (command === 'gametime') return deferEphemeral(ctx, interaction, () => gameTime(interaction, env, opts));
    if (command === 'report') return deferEphemeral(ctx, interaction, () => submitReport(interaction, env, opts));

    if (path[0] === 'admin') {
      return deferEphemeral(ctx, interaction, async () => {
        if (!(await requireCommissioner(interaction, env))) return 'Admin commands are for the Commissioner role.';
        if (command === 'admin import') return adminImport(interaction, env, opts);
        if (command === 'admin readtest') return adminReadTest(interaction, env, opts);
        if (command === 'admin staff') return adminStaff(interaction, env, opts);
        if (command === 'admin player') return adminPlayer(interaction, env, opts);
        return 'Unknown admin command.';
      });
    }
    return ephemeral('Unknown command. Try `/drew help`.');
  }
};
