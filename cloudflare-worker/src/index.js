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

// ---------------------------------------------------------------- admin

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
  '`/drew weekly-slate`, `/drew schedule` — latest posts from those channels.',
  'Commissioner: `/drew setup-check`, `/drew admin import`, `/drew admin staff`, `/drew admin player`.',
  'Game reports from screenshots are coming in the next build.'
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
      return ephemeral('This button is no longer active.');
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

    if (path[0] === 'admin') {
      return deferEphemeral(ctx, interaction, async () => {
        if (!(await requireCommissioner(interaction, env))) return 'Admin commands are for the Commissioner role.';
        if (command === 'admin import') return adminImport(interaction, env, opts);
        if (command === 'admin staff') return adminStaff(interaction, env, opts);
        if (command === 'admin player') return adminPlayer(interaction, env, opts);
        return 'Unknown admin command.';
      });
    }
    return ephemeral('Unknown command. Try `/drew help`.');
  }
};
