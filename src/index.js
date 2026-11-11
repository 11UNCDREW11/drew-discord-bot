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

const TIER_CHOICES = [
  { name: 'Franchise', value: 'Franchise' },
  { name: 'Star', value: 'Star' },
  { name: 'Core', value: 'Core' },
  { name: 'Rotation', value: 'Rotation' },
  { name: 'Development', value: 'Development' }
];
const SEASON_OPTION = { type: 4, name: 'season', description: 'Season (default: current)', required: false, min_value: 1 };

// Players and GMs use the button menu. Slash commands are kept to the minimum:
// /drew menu, /drew help, a backup /drew report, and the Commissioner's tools.
const DREW_VERSION = '2026-11-11b';
const commandDefinitions = [
  {
    type: 1,
    name: 'drew',
    description: 'League assistant',
    options: [
      { type: 1, name: 'menu', description: 'Open the league menu' },
      { type: 1, name: 'help', description: 'How the league menu works' },
      {
        type: 1,
        name: 'report',
        description: 'Backup way to report a game',
        options: [
          { type: 3, name: 'game', description: 'Type a team name', required: true, max_length: 40, autocomplete: true },
          {
            type: 3, name: 'result', description: 'Your result', required: true,
            choices: [{ name: 'We won', value: 'won' }, { name: 'We lost (fixing a no-report win)', value: 'lost' }]
          },
          { type: 11, name: 'screenshot', description: 'Game Stats screenshot', required: true }
        ]
      },
      { type: 1, name: 'setup-check', description: 'Commissioner: check setup' },
      {
        type: 2,
        name: 'admin',
        description: 'Commissioner tools',
        options: [
          { type: 1, name: 'post-menu', description: 'Post the menu buttons here' },
          {
            type: 1,
            name: 'import',
            description: 'Load a CSV file',
            options: [
              {
                type: 3, name: 'kind', description: 'What the file contains', required: true,
                choices: [
                  { name: 'Teams (franchises)', value: 'franchises' },
                  { name: 'Players', value: 'players' },
                  { name: 'Games (schedule)', value: 'fixtures' },
                  { name: 'Prices', value: 'prices' }
                ]
              },
              { type: 11, name: 'file', description: 'CSV file', required: true }
            ]
          },
          {
            type: 1,
            name: 'price',
            description: "Publish a player's tier and FP cost",
            options: [
              { type: 6, name: 'player', description: 'Player', required: true },
              { type: 4, name: 'scorecard', description: 'Scorecard total 3–15', required: false, min_value: 3, max_value: 15 },
              { type: 3, name: 'tier', description: 'Tier (with fp_cost)', required: false, choices: TIER_CHOICES },
              { type: 4, name: 'fp_cost', description: 'FP per season (with tier)', required: false, min_value: 1, max_value: 16 },
              SEASON_OPTION
            ]
          },
          {
            type: 1,
            name: 'draft',
            description: 'Run the draft',
            options: [{
              type: 3, name: 'action', description: 'What to do', required: true,
              choices: [
                { name: 'Start first-season draft', value: 'start-inaugural' },
                { name: 'Run lottery + yearly draft', value: 'start-entry' },
                { name: 'Undo the last pick', value: 'undo' },
                { name: 'Skip team on the clock', value: 'pass' },
                { name: 'End the draft now', value: 'end' }
              ]
            }]
          },
          {
            type: 1,
            name: 'readtest',
            description: 'Test screenshot reading',
            options: [
              { type: 11, name: 'screenshot', description: 'Screenshot', required: true },
              {
                type: 3, name: 'model', description: 'Reader model', required: false,
                choices: [{ name: 'Haiku', value: 'claude-haiku-5-5' }, { name: 'Sonnet', value: 'claude-sonnet-5-5' }]
              }
            ]
          },
          {
            type: 1,
            name: 'forfeit',
            description: 'Record a forfeit',
            options: [
              { type: 3, name: 'fixture', description: 'Type a team name', required: true, max_length: 40, autocomplete: true },
              {
                type: 3, name: 'forfeiting', description: 'Who forfeits', required: true,
                choices: [{ name: 'Home team', value: 'home' }, { name: 'Away team', value: 'away' }, { name: 'Both', value: 'both' }]
              },
              { type: 3, name: 'reason', description: 'Reason', required: true, max_length: 200 }
            ]
          },
          {
            type: 1,
            name: 'credit',
            description: 'Grant a ready-team credit',
            options: [
              { type: 6, name: 'player', description: 'Player', required: true },
              { type: 3, name: 'fixture', description: 'Type a team name', required: true, max_length: 40, autocomplete: true }
            ]
          },
          {
            type: 1,
            name: 'export',
            description: 'Download a CSV',
            options: [
              {
                type: 3, name: 'kind', description: 'What to export', required: true,
                choices: [{ name: 'Standings', value: 'standings' }, { name: 'Player stats', value: 'players' }, { name: 'Game lines', value: 'games' }]
              },
              SEASON_OPTION
            ]
          },
          { type: 1, name: 'publish', description: 'Post standings and leaders', options: [SEASON_OPTION] },
          {
            type: 1,
            name: 'sign',
            description: 'Sign a player directly',
            options: [
              { type: 6, name: 'player', description: 'Player', required: true },
              { type: 3, name: 'franchise', description: 'Team ID', required: true, max_length: 40 },
              { type: 3, name: 'tier', description: 'Tier', required: true, choices: TIER_CHOICES },
              { type: 4, name: 'fp_cost', description: 'FP per season', required: true, min_value: 1, max_value: 16 },
              { type: 4, name: 'years', description: 'Seasons', required: true, choices: [{ name: '1', value: 1 }, { name: '2', value: 2 }, { name: '3', value: 3 }] },
              {
                type: 3, name: 'source', description: 'FP cost source', required: true,
                choices: [{ name: 'Scorecard', value: 'Scorecard table' }, { name: 'Value Index', value: 'Value Index' }, { name: 'Committee', value: 'Committee adjustment' }, { name: 'Band minimum', value: 'Band minimum' }]
              },
              { type: 5, name: 'player_option', description: 'Loyalty option year', required: false }
            ]
          },
          {
            type: 1,
            name: 'release',
            description: 'Release a player directly',
            options: [
              { type: 6, name: 'player', description: 'Player', required: true },
              { type: 3, name: 'method', description: 'How', required: true, choices: [{ name: 'Buyout', value: 'buyout' }, { name: 'Dead cap', value: 'deadcap' }] },
              { type: 3, name: 'reason', description: 'Reason', required: true, max_length: 200 }
            ]
          },
          {
            type: 1,
            name: 'trade',
            description: 'Record a trade directly',
            options: [
              { type: 3, name: 'franchise_a', description: 'Team A ID', required: true, max_length: 40 },
              { type: 3, name: 'players_a', description: 'Player IDs leaving A', required: true, max_length: 200 },
              { type: 3, name: 'franchise_b', description: 'Team B ID', required: true, max_length: 40 },
              { type: 3, name: 'players_b', description: 'Player IDs leaving B', required: false, max_length: 200 }
            ]
          },
          {
            type: 1,
            name: 'option',
            description: 'Record an option decision',
            options: [
              { type: 6, name: 'player', description: 'Player', required: true },
              { type: 3, name: 'decision', description: 'Decision', required: true, choices: [{ name: 'Exercise', value: 'exercise' }, { name: 'Decline', value: 'decline' }] }
            ]
          },
          {
            type: 1,
            name: 'season',
            description: 'Start or close the season',
            options: [{ type: 3, name: 'action', description: 'Action', required: true, choices: [{ name: 'Start', value: 'start' }, { name: 'Close', value: 'close' }] }]
          },
          {
            type: 1,
            name: 'staff',
            description: 'Set captain and GM',
            options: [
              { type: 3, name: 'franchise', description: 'Team ID', required: true, max_length: 40 },
              { type: 6, name: 'captain', description: 'Captain', required: true },
              { type: 6, name: 'gm', description: 'GM (optional)', required: false }
            ]
          },
          {
            type: 1,
            name: 'player',
            description: 'Add or update a player',
            options: [
              { type: 6, name: 'user', description: 'Member', required: true },
              { type: 3, name: 'player_id', description: 'Player ID', required: true, max_length: 40 },
              { type: 3, name: 'name', description: 'Display name', required: true, max_length: 60 },
              { type: 3, name: 'franchise', description: 'Team ID (blank = free agent)', required: false, max_length: 40 },
              { type: 3, name: 'position', description: 'Position', required: false, max_length: 20 }
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
    return { ok: false, status: 0, detail: 'DISCORD_BOT_TOKEN, DISCORD_APPLICATION_ID, or DISCORD_GUILD_ID is missing in Cloudflare.' };
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
    const detail = (await response.text().catch(() => '')).slice(0, 400);
    console.error(`Command registration failed with HTTP ${response.status}: ${detail}`);
    return { ok: false, status: response.status, detail };
  }
  console.log('DREW slash commands registered for the configured league server.');
  return { ok: true };
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
    if (content && typeof content === 'object' && content.file) await editOriginalWithFile(interaction, content);
    else if (content && typeof content === 'object') await editOriginal(interaction, content);
    else await editOriginal(interaction, { content });
  })());
  return json({ type: 5, data: { flags: EPHEMERAL } });
}

// Replace the "thinking…" reply with text plus one attached file (used for CSV exports).
async function editOriginalWithFile(interaction, { content, file }) {
  const url = `https://discord.com/api/v10/webhooks/${interaction.application_id}/${interaction.token}/messages/@original`;
  const form = new FormData();
  form.append('payload_json', JSON.stringify({
    content, allowed_mentions: { parse: [] }, attachments: [{ id: 0, filename: file.name }]
  }));
  form.append('files[0]', new Blob([file.text], { type: 'text/csv' }), file.name);
  const response = await fetch(url, { method: 'PATCH', body: form });
  if (!response.ok) console.error(`File reply could not be delivered; Discord returned HTTP ${response.status}.`);
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
  players: ['player_id', 'display_name', 'discord_id', 'franchise_id', 'position'],
  fixtures: ['fixture_id', 'season', 'week', 'home_franchise_id', 'away_franchise_id'],
  prices: ['player_id']
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
  if (!rows.length) return 'No gamertag linked yet.';
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
  if (!franchiseIds.length) return 'You aren\'t on a team yet. Once the Commissioner adds you, your games show up here.';

  const lines = [];
  for (const fid of franchiseIds) {
    const franchise = await franchiseOf(db, fid);
    const rows = (await db.prepare(
      "SELECT * FROM fixtures WHERE (home_id = ? OR away_id = ?) AND status NOT IN ('Final') ORDER BY season, week, fixture_id LIMIT 15"
    ).bind(fid, fid).all()).results ?? [];
    lines.push(`**${franchise?.name ?? fid}** — games still to play or report`);
    if (!rows.length) lines.push('None right now.');
    for (const fx of rows) {
      const home = fx.home_id === fid;
      const opponent = await franchiseOf(db, home ? fx.away_id : fx.home_id);
      const status = fx.status === 'Reported' ? 'reported, waiting on the other team'
        : fx.status === 'Unreported' ? 'no report yet: home team has the win for now'
          : fx.agreed_start_utc ? `starts ${when(fx.agreed_start_utc)}`
            : fx.proposed_start_utc ? `time suggested (${when(fx.proposed_start_utc)}), waiting for the other team to confirm` : 'no time set yet';
      lines.push(`Week ${fx.week} · ${home ? 'vs' : '@'} **${opponent?.name ?? '?'}** (${home ? 'home' : 'away'}) · ${status}`);
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
  if (!fx) return 'That game wasn\'t found. Open the menu and pick it from the list.';
  if (!['Scheduled', 'Time proposed', 'Time set'].includes(fx.status)) {
    return 'This game has already been reported, so its time can\'t be changed. Contact the Commissioner if it\'s wrong.';
  }
  const startUtc = localToUtc(opts.date, opts.time, opts.timezone);
  if (!startUtc) return 'DREW couldn\'t read that time. Type it like `8:30 PM` or `20:30`.';
  const startMs = Date.parse(startUtc);
  if (startMs < Date.now() - 2 * 86400000 || startMs > Date.now() + 45 * 86400000) {
    return 'That time is too far in the past or future. Check the day.';
  }

  const [home, away] = await Promise.all([franchiseOf(db, fx.home_id), franchiseOf(db, fx.away_id)]);
  const mine = new Set((await staffFranchises(db, me)).map((f) => f.franchise_id));
  const roles = await memberRoleNames(interaction, env);
  const side = mine.has(fx.home_id) ? fx.home_id : mine.has(fx.away_id) ? fx.away_id : null;
  if (fx.agreed_start_utc && Date.parse(fx.agreed_start_utc) <= Date.now() && !isCommissioner(roles)) {
    return 'This game\'s start time has already passed, so only the Commissioner can change it.';
  }
  const now = nowIso();
  const label = `**Week ${fx.week}: ${home?.name ?? fx.home_id}** (home) vs **${away?.name ?? fx.away_id}**`;

  if (!side) {
    if (!isCommissioner(roles)) return 'Only the two teams\' captains or GMs, or the Commissioner, can set this game\'s time.';
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
    return `Start time set: ${when(startUtc)}.`;
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
      `Suggested start: ${when(startUtc)} — by <@${me}>`,
      mentions.length
        ? `${mentions.map((id) => `<@${id}>`).join(' ')} — press **Confirm time**, or **Suggest another time**.`
        : `${otherFranchise?.name ?? 'The other team'} has no captain or GM set in DREW yet. Ask the Commissioner.`
    ].join('\n'),
    allowed_mentions: { users: mentions },
    components: [{
      type: 1,
      components: [
        { type: 2, style: 3, label: 'Confirm time', custom_id: `gtime:confirm:${fixtureId}:${unix(startUtc)}` },
        { type: 2, style: 2, label: 'Suggest another time', custom_id: `gt:other:${fixtureId}` }
      ]
    }]
  });
  return `Suggested ${when(startUtc)}. It becomes official when ${otherFranchise?.name ?? 'the other team'} confirms. They've been tagged in #game-reports.`;
}

async function gameTimeConfirm(interaction, env, fixtureId, proposedUnix) {
  const db = requireDb(env);
  const me = invokerId(interaction);
  const fx = await db.prepare('SELECT * FROM fixtures WHERE fixture_id = ?').bind(fixtureId).first();
  if (!fx || fx.status !== 'Time proposed' || !fx.proposed_start_utc || unix(fx.proposed_start_utc) !== Number(proposedUnix)) {
    await editOriginal(interaction, { components: [] });
    await followUp(interaction, 'This time is out of date: someone suggested a newer time, or the time is already set. Check **My games** in the menu.');
    return;
  }
  const mine = new Set((await staffFranchises(db, me)).map((f) => f.franchise_id));
  const otherSide = fx.proposed_by_franchise === fx.home_id ? fx.away_id : fx.home_id;
  if (!mine.has(otherSide)) {
    const roles = await memberRoleNames(interaction, env);
    if (!isCommissioner(roles)) {
      await followUp(interaction, 'Only the other team\'s captain or GM (or the Commissioner) can confirm this time.');
      return;
    }
  }
  const now = nowIso();
  await db.batch([
    db.prepare("UPDATE fixtures SET agreed_start_utc = proposed_start_utc, time_confirmed_by = ?, status = 'Time set', updated_at = ? WHERE fixture_id = ?")
      .bind(me, now, fixtureId),
    audit(db, me, 'fixtures', fixtureId, 'agreed_start_utc', null, fx.proposed_start_utc, 'Confirmed by the other franchise')
  ]);
  const original = interaction.message?.content?.split('\n').slice(0, 2).join('\n') ?? '**Game time**';
  await editOriginal(interaction, {
    content: `${original}\n**Confirmed** by <@${me}>. Game time: ${when(fx.proposed_start_utc)}. The winner has 24 hours from this time to report.`,
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
    `**Game report #${report.report_id}** · Week ${fx.week} · ${home.name} (home) vs ${away.name} · game ${fx.fixture_id}`,
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
  const fixtureId = String(opts.fixture ?? opts.game ?? '').trim();
  const attachment = interaction.data?.resolved?.attachments?.[opts.screenshot];
  if (!attachment) return 'Add the box-score screenshot.';
  if (!String(attachment.content_type ?? '').startsWith('image/')) return 'The screenshot must be an image (PNG or JPG).';
  if (attachment.size > 9_000_000) return 'That image is over 9 MB. Send a smaller screenshot.';

  const fx = await db.prepare('SELECT * FROM fixtures WHERE fixture_id = ?').bind(fixtureId).first();
  if (!fx) return 'That game wasn\'t found. Open the menu and pick it from the list.';
  const [home, away] = await Promise.all([franchiseOf(db, fx.home_id), franchiseOf(db, fx.away_id)]);
  const mine = new Set((await staffFranchises(db, me)).map((f) => f.franchise_id));
  const side = mine.has(fx.home_id) ? fx.home_id : mine.has(fx.away_id) ? fx.away_id : null;
  if (!side) return 'Only a captain or GM of one of these two teams can report this game.';

  const inCorrectionWindow = fx.status === 'Unreported' && Date.now() - Date.parse(fx.unreported_at ?? fx.updated_at) <= CORRECTION_WINDOW_MS;
  if (fx.status === 'Final') return 'This game is already final. Contact the Commissioner if the result is wrong.';
  if (fx.status === 'Reported') return 'This game already has a report waiting. The other team can press **Looks right** or **Something\'s wrong** on the card in #game-reports.';
  if (fx.status === 'Unreported' && !inCorrectionWindow) return 'The 48 hours to fix a no-report result have passed. Contact the Commissioner.';
  const otherSide = side === fx.home_id ? fx.away_id : fx.home_id;
  const claimedWinnerId = opts.winner ? String(opts.winner) : opts.result === 'won' ? side : otherSide;
  if (![fx.home_id, fx.away_id].includes(claimedWinnerId)) return 'Pick which team won.';
  if (claimedWinnerId !== side && !inCorrectionWindow) {
    return 'Only the winning team reports the game. If you lost, you don\'t need to do anything: the winner reports, and you can check it on the card in #game-reports.';
  }

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
      ? 'Screenshot reading isn\'t set up yet. Tell the Commissioner. Your report was not sent.'
      : 'DREW couldn\'t read the screenshot right now. Your report was not sent. Try again in a few minutes; if it keeps failing, contact the Commissioner before the 24-hour deadline.';
  }
  if (!read.data?.readable) {
    return `DREW couldn't read that screenshot${read.data?.problem ? `: ${read.data.problem}` : ''}. Upload a clear, full screenshot of the Game Stats page showing both teams. Your report was not sent.`;
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
    ? `Winner: **${claimedWinnerId === fx.home_id ? home.name : away.name}** · ${loserStaff.map((id) => `<@${id}>`).join(' ') || otherFranchise.name}: press **Looks right** or **Something's wrong** within 24 hours. If you don't, it stands.`
    : `**The committee will check this one** — ${outcome.checks.filter((c) => !c.ok).map((c) => c.name).join(', ')}. ${loserStaff.map((id) => `<@${id}>`).join(' ')} you can still respond below.`;
  const card = await postToChannel(env, 'game-reports', {
    content: reportCard(fx, home, away, report, outcome, read.data, statusLine, me),
    allowed_mentions: { users: loserStaff },
    embeds: [{ title: 'Screenshot as submitted', image: { url: attachment.url } }],
    components: [{
      type: 1,
      components: [
        { type: 2, style: 3, label: 'Looks right', custom_id: `rpt:confirm:${report.report_id}` },
        { type: 2, style: 4, label: 'Something\'s wrong', custom_id: `rpt:dispute:${report.report_id}` }
      ]
    }]
  });
  await db.prepare('UPDATE reports SET card_message_id = ? WHERE report_id = ?').bind(card.messageId, report.report_id).run();
  if (!outcome.clean) await postReviewItem(env, db, report, fx, 'checks failed', checkSummary(outcome.checks));

  return outcome.clean
    ? `Report sent (#${report.report_id}) and every check passed. It's posted in #game-reports for ${otherFranchise.name} to look over.`
    : `Report sent (#${report.report_id}), but some checks didn't pass, so the committee will look at it:\n${checkSummary(outcome.checks)}`;
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
    await followUp(interaction, 'Only the other team\'s captain or GM can respond to this report.');
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
      await followUp(interaction, 'Thanks, noted. The committee still needs to check this report before it counts.');
    }
  }
}

function disputeModal(reportId) {
  return json({
    type: 9,
    data: {
      custom_id: `rptmodal:${reportId}`,
      title: `What's wrong with report #${reportId}?`,
      components: [{
        type: 18,
        label: 'Tell the committee what is wrong',
        description: 'For example: wrong winner, a stat is off, a player is missing.',
        component: { type: 4, custom_id: 'reason', style: 2, min_length: 5, max_length: 500, required: true }
      }]
    }
  });
}

async function disputeSubmit(interaction, env, reportId) {
  const db = requireDb(env);
  const me = invokerId(interaction);
  const reason = String(modalValues(interaction).reason ?? '').trim();
  const report = await db.prepare('SELECT * FROM reports WHERE report_id = ?').bind(reportId).first();
  if (!report || ['Final', 'Rejected', 'Disputed'].includes(report.state)) {
    await followUp(interaction, `Report #${reportId} is already ${report ? report.state.toLowerCase() : 'gone'}.`);
    return;
  }
  const fx = await db.prepare('SELECT * FROM fixtures WHERE fixture_id = ?').bind(report.fixture_id).first();
  const loserId = report.claimed_result === fx.home_id ? fx.away_id : fx.home_id;
  const mine = new Set((await staffFranchises(db, me)).map((f) => f.franchise_id));
  if (!mine.has(loserId)) {
    await followUp(interaction, 'Only the other team\'s captain or GM can flag this report.');
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
  if (lines.length > 3) lines[3] = `**Flagged** by <@${me}> — the committee will look at it.`;
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
      content: `**Game report #${reportId}** (Week ${fx.week}, game ${fx.fixture_id}) was sent back by the committee. <@${submitter}> please send a new screenshot: \`/drew menu\` → **Report a game**.`,
      allowed_mentions: { users: [submitter] },
      embeds: [],
      components: []
    });
    await editOriginal(interaction, { content: stamp('Rejected — captain asked to resubmit'), components: [] });
  }
}

// ---------------------------------------------------------------- timers (step 3, runs every hour)

const HOUR = 3600000;

// Columns added after the first schema. ALTER fails harmlessly once a column exists.
let schemaChecked = false;
async function ensureSchema(db) {
  if (schemaChecked) return;
  for (const statement of [
    'ALTER TABLE fixtures ADD COLUMN reminders_sent INTEGER NOT NULL DEFAULT 0',
    'ALTER TABLE fixtures ADD COLUMN unreported_at TEXT',
    'CREATE TABLE IF NOT EXISTS eligibility_credits (player_id TEXT NOT NULL, fixture_id TEXT NOT NULL, granted_by TEXT NOT NULL, granted_at TEXT NOT NULL, PRIMARY KEY (player_id, fixture_id))',
    'CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT)',
    'CREATE TABLE IF NOT EXISTS contracts (contract_id INTEGER PRIMARY KEY AUTOINCREMENT, player_id TEXT NOT NULL, franchise_id TEXT NOT NULL, tier TEXT NOT NULL, pcv INTEGER NOT NULL, fp_cost INTEGER NOT NULL, fp_source TEXT, start_season INTEGER NOT NULL, years INTEGER NOT NULL, option_status TEXT NOT NULL DEFAULT \'None\', status TEXT NOT NULL, ended_season INTEGER, signed_at TEXT, signed_by TEXT, ended_at TEXT)',
    'CREATE INDEX IF NOT EXISTS idx_contracts_franchise ON contracts (franchise_id, status)',
    'CREATE INDEX IF NOT EXISTS idx_contracts_player ON contracts (player_id, status)',
    'CREATE TABLE IF NOT EXISTS fp_bank (franchise_id TEXT NOT NULL, season INTEGER NOT NULL, opening_balance INTEGER NOT NULL, PRIMARY KEY (franchise_id, season))',
    'CREATE TABLE IF NOT EXISTS fp_ledger (id INTEGER PRIMARY KEY AUTOINCREMENT, franchise_id TEXT NOT NULL, season INTEGER NOT NULL, kind TEXT NOT NULL, amount INTEGER NOT NULL, from_current INTEGER NOT NULL DEFAULT 0, from_bank INTEGER NOT NULL DEFAULT 0, note TEXT, at TEXT NOT NULL)',
    'CREATE TABLE IF NOT EXISTS pending_tx (id INTEGER PRIMARY KEY AUTOINCREMENT, kind TEXT NOT NULL, payload TEXT NOT NULL, created_by TEXT NOT NULL, created_at TEXT NOT NULL, status TEXT NOT NULL, decided_by TEXT, decided_at TEXT)',
    'CREATE TABLE IF NOT EXISTS player_prices (player_id TEXT NOT NULL, season INTEGER NOT NULL, tier TEXT NOT NULL, fp_cost INTEGER NOT NULL, source TEXT, set_by TEXT, set_at TEXT, PRIMARY KEY (player_id, season))'
  ]) {
    try { await db.prepare(statement).run(); } catch { /* column already exists */ }
  }
  schemaChecked = true;
}

async function runTimers(env, nowMs = Date.now()) {
  const db = requireDb(env);
  await ensureSchema(db);
  const now = new Date(nowMs).toISOString();
  const actor = 'DREW (timer)';
  const summary = { reminders: 0, unreported: 0, closed: 0, finalized: 0 };
  const franchiseCache = new Map();
  const franchise = async (id) => {
    if (!franchiseCache.has(id)) franchiseCache.set(id, await franchiseOf(db, id));
    return franchiseCache.get(id);
  };
  const post = async (message) => {
    try { await postToChannel(env, 'game-reports', message); } catch (error) { console.error(`Timer post failed: ${error.message}`); }
  };

  // 1. Reminders at 12 and 20 hours, then the Unreported award at 24 hours.
  const waiting = (await db.prepare(
    "SELECT * FROM fixtures WHERE status = 'Time set' AND agreed_start_utc IS NOT NULL AND agreed_start_utc <= ?"
  ).bind(new Date(nowMs - 12 * HOUR).toISOString()).all()).results ?? [];
  for (const fx of waiting) {
    const age = nowMs - Date.parse(fx.agreed_start_utc);
    const home = await franchise(fx.home_id);
    const away = await franchise(fx.away_id);
    const mentions = [...new Set([...staffMentions(home), ...staffMentions(away)])];
    const tags = mentions.map((id) => `<@${id}>`).join(' ');
    const label = `**Week ${fx.week}: ${home?.name ?? fx.home_id}** (home) vs **${away?.name ?? fx.away_id}**`;

    if (age >= 24 * HOUR) {
      await db.batch([
        db.prepare("UPDATE fixtures SET status = 'Unreported', result_type = 'Unreported', winner_id = home_id, home_score = NULL, away_score = NULL, unreported_at = ?, updated_at = ? WHERE fixture_id = ? AND status = 'Time set'")
          .bind(now, now, fx.fixture_id),
        audit(db, actor, 'fixtures', fx.fixture_id, 'status', 'Time set', 'Unreported', 'No report within 24 hours of the agreed start; home team awarded the win')
      ]);
      summary.unreported += 1;
      await post({
        content: `${label}\nNobody reported this game within 24 hours, so **${home?.name ?? 'the home team'}** gets the win (home-team rule). It counts in the standings only: no player stats and no games played.\nEither team can still send the screenshot (\`/drew menu\` → **Report a game**) until <t:${Math.floor((nowMs + CORRECTION_WINDOW_MS) / 1000)}:f>, and the real result will replace this. ${tags}`,
        allowed_mentions: { users: mentions }
      });
      continue;
    }
    const due = age >= 20 * HOUR ? 2 : 1;
    if ((fx.reminders_sent ?? 0) >= due) continue;
    await db.batch([
      db.prepare('UPDATE fixtures SET reminders_sent = ? WHERE fixture_id = ?').bind(due, fx.fixture_id),
      audit(db, actor, 'fixtures', fx.fixture_id, 'reminders_sent', fx.reminders_sent ?? 0, due, `${due === 1 ? '12' : '20'}-hour reminder`)
    ]);
    summary.reminders += 1;
    const deadline = Math.floor((Date.parse(fx.agreed_start_utc) + 24 * HOUR) / 1000);
    await post({
      content: `${label}\nReminder: no report yet. The winning team needs to send the screenshot (\`/drew menu\` → **Report a game**) by <t:${deadline}:f> (<t:${deadline}:R>). If nobody does, the home team gets the win. ${tags}`,
      allowed_mentions: { users: mentions }
    });
  }

  // 2. Close correction windows after 48 hours: the Unreported result becomes final.
  const expired = (await db.prepare(
    "SELECT * FROM fixtures WHERE status = 'Unreported' AND COALESCE(unreported_at, updated_at) <= ?"
  ).bind(new Date(nowMs - CORRECTION_WINDOW_MS).toISOString()).all()).results ?? [];
  for (const fx of expired) {
    await db.batch([
      db.prepare("UPDATE fixtures SET status = 'Final', updated_at = ? WHERE fixture_id = ? AND status = 'Unreported'").bind(now, fx.fixture_id),
      audit(db, actor, 'fixtures', fx.fixture_id, 'status', 'Unreported', 'Final', 'Correction window closed with no screenshot; Unreported result is final')
    ]);
    summary.closed += 1;
  }

  // 3. A clean report with no response for 48 hours becomes final
  //    (24 hours to confirm or dispute, then 24 hours for contrary evidence).
  const stale = (await db.prepare(
    "SELECT * FROM reports WHERE state = 'Pending' AND opponent_response IS NULL AND submitted_at <= ?"
  ).bind(new Date(nowMs - 48 * HOUR).toISOString()).all()).results ?? [];
  for (const report of stale) {
    await finalizeReport(env, db, report, actor, 'no response from the other team within 24 hours and no contrary evidence within the next 24');
    summary.finalized += 1;
  }

  if (Object.values(summary).some(Boolean)) console.log('Timer run:', JSON.stringify(summary));
  return summary;
}

// ---------------------------------------------------------------- standings and stats (step 4)
// Pure calculations live here so the website can reuse them later.

const PLAYOFF_SPOTS = 6;
const ON_COURT_NEEDED = 32;
const APPEARANCES_NEEDED = 10;
const LEADER_MIN_GP = 5;
const EFG_MIN_GP = 16;
const EFG_MIN_FGA = 50;

async function currentSeason(db) {
  const row = await db.prepare('SELECT MAX(season) AS s FROM fixtures').first();
  return row?.s ?? 1;
}

// Which games count, and how, under Rulebook Sections 12 and 14.
function gameEffect(fx) {
  if (fx.status === 'Final' && fx.result_type === 'Played') return 'played';
  if ((fx.status === 'Final' || fx.status === 'Unreported') && fx.result_type === 'Unreported') return 'unreported';
  if (fx.status === 'Final' && fx.result_type === 'Forfeit') return 'forfeit';
  if (fx.status === 'Final' && fx.result_type === 'Double forfeit') return 'double';
  return null;
}

function computeStandings(fixtures, franchises) {
  const rows = new Map(franchises.map((f) => [f.franchise_id, {
    franchise_id: f.franchise_id, name: f.name, gp: 0, w: 0, l: 0, onCourt: 0, pf: 0, pa: 0, scheduled: 0, forfeits: 0
  }]));
  const results = [];
  for (const fx of fixtures) {
    for (const id of [fx.home_id, fx.away_id]) if (rows.has(id)) rows.get(id).scheduled += 1;
    const effect = gameEffect(fx);
    if (!effect) continue;
    const home = rows.get(fx.home_id);
    const away = rows.get(fx.away_id);
    if (!home || !away) continue;
    home.gp += 1; away.gp += 1;
    if (effect === 'double') {
      home.l += 1; away.l += 1; home.forfeits += 1; away.forfeits += 1;
      continue;
    }
    const winner = fx.winner_id === fx.home_id ? home : away;
    const loser = winner === home ? away : home;
    winner.w += 1; loser.l += 1;
    results.push({ winner: winner.franchise_id, loser: loser.franchise_id });
    if (effect === 'forfeit') loser.forfeits += 1;
    if (effect === 'played') {
      home.onCourt += 1; away.onCourt += 1;
      home.pf += fx.home_score ?? 0; home.pa += fx.away_score ?? 0;
      away.pf += fx.away_score ?? 0; away.pa += fx.home_score ?? 0;
    }
  }
  const list = [...rows.values()].map((r) => ({ ...r, pct: r.gp ? r.w / r.gp : 0, diff: r.pf - r.pa }));
  list.sort((a, b) => b.pct - a.pct || b.w - a.w);

  // Tiebreakers among teams with the same record: head-to-head, point differential, points scored.
  const ordered = [];
  for (let i = 0; i < list.length;) {
    let j = i + 1;
    while (j < list.length && list[j].pct === list[i].pct && list[j].w === list[i].w) j += 1;
    const group = list.slice(i, j);
    if (group.length > 1) {
      const ids = new Set(group.map((g) => g.franchise_id));
      for (const g of group) {
        g.h2h = results.filter((r) => ids.has(r.winner) && ids.has(r.loser))
          .reduce((n, r) => n + (r.winner === g.franchise_id ? 1 : r.loser === g.franchise_id ? -1 : 0), 0);
      }
      group.sort((a, b) => b.h2h - a.h2h || b.diff - a.diff || b.pf - a.pf);
      for (let k = 1; k < group.length; k += 1) {
        const a = group[k - 1];
        const b = group[k];
        if (a.h2h === b.h2h && a.diff === b.diff && a.pf === b.pf) { a.unresolvedTie = true; b.unresolvedTie = true; }
      }
    }
    ordered.push(...group);
    i = j;
  }

  // Playoff picture: top six among teams that have (or can still reach) 32 on-court games.
  let seed = 0;
  ordered.forEach((r, index) => {
    r.rank = index + 1;
    r.remaining = Math.max(0, r.scheduled - r.gp);
    r.canQualify = r.onCourt + r.remaining >= ON_COURT_NEEDED;
    r.onCourtMet = r.onCourt >= ON_COURT_NEEDED;
    r.seed = r.canQualify && seed < PLAYOFF_SPOTS ? (seed += 1) : null;
  });
  return ordered;
}

function formatStandings(rows, season) {
  if (!rows.length) return 'No franchises yet.';
  const lines = rows.map((r) => {
    const tag = r.seed ? `${r.seed <= 2 ? 'bye' : 'in'}` : r.canQualify ? '' : 'out*';
    return `${String(r.rank).padStart(2)} ${r.name.slice(0, 16).padEnd(16)} ${`${r.w}-${r.l}`.padStart(5)} ${String(r.onCourt).padStart(3)}/${ON_COURT_NEEDED} ${(r.diff > 0 ? `+${r.diff}` : String(r.diff)).padStart(5)} ${tag}${r.unresolvedTie ? ' tie' : ''}`;
  });
  const notes = [
    `Played = games actually played (forfeits and no-report wins don't count). The top ${PLAYOFF_SPOTS} teams with ${ON_COURT_NEEDED}+ played make the playoffs; the top 2 skip the first round.`,
    rows.some((r) => !r.canQualify) ? '*out = can no longer reach 32 played.' : null,
    rows.some((r) => r.unresolvedTie) ? 'tie = still tied after head-to-head, point difference, and points scored; the Commissioner breaks it by public draw.' : null
  ].filter(Boolean);
  return `**Season ${season} standings**\n\`\`\`\n #  Team              W-L  Played  +/-\n${lines.join('\n')}\n\`\`\`\n${notes.join('\n')}`;
}

async function loadSeason(db, season) {
  const fixtures = (await db.prepare('SELECT * FROM fixtures WHERE season = ?').bind(season).all()).results ?? [];
  const franchises = (await db.prepare('SELECT * FROM franchises ORDER BY name').all()).results ?? [];
  return { fixtures, franchises };
}

async function playerSeasonStats(db, season) {
  const rows = (await db.prepare(`
    SELECT pg.player_id, p.display_name, p.discord_id, COALESCE(p.franchise_id, pg.franchise_id) AS franchise_id,
      COUNT(*) AS gp, SUM(pg.pts) AS pts, SUM(pg.reb) AS reb, SUM(pg.ast) AS ast, SUM(pg.stl) AS stl, SUM(pg.blk) AS blk,
      SUM(pg.tov) AS tov, SUM(pg.fgm) AS fgm, SUM(pg.fga) AS fga, SUM(pg.tpm) AS tpm, SUM(pg.tpa) AS tpa,
      SUM(pg.ftm) AS ftm, SUM(pg.fta) AS fta
    FROM player_games pg
    JOIN fixtures f ON f.fixture_id = pg.fixture_id
    LEFT JOIN players p ON p.player_id = pg.player_id
    WHERE f.season = ? AND f.status = 'Final' AND f.result_type = 'Played'
    GROUP BY pg.player_id`).bind(season).all()).results ?? [];
  return rows.map((r) => ({ ...r, efg: r.fga ? (r.fgm + 0.5 * r.tpm) / r.fga : null }));
}

const perGame = (total, gp) => (gp ? (total / gp).toFixed(1) : '0.0');
const pctText = (value) => (value == null ? '—' : `${(value * 100).toFixed(1)}%`);

async function eligibilityRows(db, season, franchiseId) {
  return (await db.prepare(`
    SELECT p.player_id, p.display_name, p.discord_id,
      (SELECT COUNT(*) FROM player_games pg JOIN fixtures f ON f.fixture_id = pg.fixture_id
        WHERE pg.player_id = p.player_id AND f.season = ? AND f.status = 'Final' AND f.result_type = 'Played') AS appearances,
      (SELECT COUNT(*) FROM eligibility_credits c JOIN fixtures f ON f.fixture_id = c.fixture_id
        WHERE c.player_id = p.player_id AND f.season = ?) AS credits
    FROM players p WHERE p.franchise_id = ? ORDER BY p.display_name`).bind(season, season, franchiseId).all()).results ?? [];
}

async function myFranchiseId(db, discordId) {
  const staff = await staffFranchises(db, discordId);
  if (staff.length) return staff[0].franchise_id;
  return (await db.prepare('SELECT franchise_id FROM players WHERE discord_id = ?').bind(discordId).first())?.franchise_id ?? null;
}

async function standingsCommand(env, opts) {
  const db = requireDb(env);
  const season = opts.season ?? await currentSeason(db);
  const { fixtures, franchises } = await loadSeason(db, season);
  return formatStandings(computeStandings(fixtures, franchises), season);
}

async function statsCommand(interaction, env, opts) {
  const db = requireDb(env);
  const season = opts.season ?? await currentSeason(db);
  const target = opts.player ?? invokerId(interaction);
  const player = await db.prepare('SELECT * FROM players WHERE discord_id = ?').bind(target).first();
  if (!player) return target === invokerId(interaction) ? 'You aren\'t on a league roster yet.' : 'That member isn\'t a league player.';
  const s = (await playerSeasonStats(db, season)).find((r) => r.player_id === player.player_id);
  const elig = (await eligibilityRows(db, season, player.franchise_id ?? '')).find((r) => r.player_id === player.player_id);
  const franchise = player.franchise_id ? await franchiseOf(db, player.franchise_id) : null;
  const header = `**${player.display_name}** · ${franchise?.name ?? 'Free agent'}${player.position ? ` · ${player.position}` : ''} · Season ${season}`;
  const price = await db.prepare('SELECT tier, fp_cost FROM player_prices WHERE player_id = ? AND season = ?').bind(player.player_id, season).first().catch(() => null);
  const priceLine = price && !player.franchise_id ? `Published price: ${price.tier} · ${price.fp_cost} FP per season` : null;
  if (!s) return [header, 'No games played yet this season.', priceLine].filter(Boolean).join('\n');
  const efgNote = s.gp >= EFG_MIN_GP && s.fga >= EFG_MIN_FGA ? '' : ` (qualifies at ${EFG_MIN_GP} GP and ${EFG_MIN_FGA} FGA)`;
  const appearances = (elig?.appearances ?? s.gp) + (elig?.credits ?? 0);
  return [
    header,
    `GP ${s.gp} · ${perGame(s.pts, s.gp)} PTS · ${perGame(s.reb, s.gp)} REB · ${perGame(s.ast, s.gp)} AST · ${perGame(s.stl, s.gp)} STL · ${perGame(s.blk, s.gp)} BLK · ${perGame(s.tov, s.gp)} TOV`,
    `FG ${s.fgm}/${s.fga} · 3P ${s.tpm}/${s.tpa} · FT ${s.ftm}/${s.fta} · eFG% ${pctText(s.efg)}${efgNote}`,
    `Season totals: ${s.pts} PTS, ${s.reb} REB, ${s.ast} AST, ${s.stl} STL, ${s.blk} BLK`,
    `Playoff eligibility: ${appearances} of ${APPEARANCES_NEEDED} games${appearances >= APPEARANCES_NEEDED ? ' ✅ eligible' : ''}${elig?.credits ? ` (includes ${elig.credits} forfeit credit${elig.credits > 1 ? 's' : ''})` : ''}`,
    priceLine
  ].filter(Boolean).join('\n');
}

function leaderList(stats, category) {
  if (category === 'efg') {
    return stats.filter((r) => r.gp >= EFG_MIN_GP && r.fga >= EFG_MIN_FGA)
      .sort((a, b) => b.efg - a.efg).slice(0, 10).map((r) => ({ r, value: pctText(r.efg) }));
  }
  return stats.filter((r) => r.gp >= LEADER_MIN_GP)
    .sort((a, b) => b[category] / b.gp - a[category] / a.gp || b[category] - a[category]).slice(0, 10)
    .map((r) => ({ r, value: perGame(r[category], r.gp) }));
}

const CATEGORY_NAMES = { pts: 'Points', reb: 'Rebounds', ast: 'Assists', stl: 'Steals', blk: 'Blocks', tpm: '3-pointers made', efg: 'Effective FG%' };

function formatLeaders(list, category, season, franchiseNames) {
  const minimum = category === 'efg' ? `${EFG_MIN_GP}+ GP and ${EFG_MIN_FGA}+ FGA` : `${LEADER_MIN_GP}+ GP`;
  if (!list.length) return `**${CATEGORY_NAMES[category]} leaders · Season ${season}**\nNobody qualifies yet (${minimum}).`;
  const lines = list.map(({ r, value }, i) => `${String(i + 1).padStart(2)} ${String(r.display_name ?? r.player_id).slice(0, 18).padEnd(18)} ${String(franchiseNames[r.franchise_id] ?? '').slice(0, 12).padEnd(12)} ${String(value).padStart(6)}`);
  return `**${CATEGORY_NAMES[category]} leaders · Season ${season}** (${minimum}${category === 'efg' ? '' : ', per game'})\n\`\`\`\n${lines.join('\n')}\n\`\`\``;
}

async function leadersCommand(env, opts) {
  const db = requireDb(env);
  const season = opts.season ?? await currentSeason(db);
  const names = Object.fromEntries(((await db.prepare('SELECT franchise_id, name FROM franchises').all()).results ?? []).map((f) => [f.franchise_id, f.name]));
  return formatLeaders(leaderList(await playerSeasonStats(db, season), opts.category), opts.category, season, names);
}

async function eligibilityCommand(interaction, env, opts) {
  const db = requireDb(env);
  const season = opts.season ?? await currentSeason(db);
  const franchiseId = opts.franchise ? String(opts.franchise).trim() : await myFranchiseId(db, invokerId(interaction));
  if (!franchiseId) return 'You aren\'t on a team.';
  const franchise = await franchiseOf(db, franchiseId);
  if (!franchise) return 'That team wasn\'t found.';
  const rows = await eligibilityRows(db, season, franchiseId);
  if (!rows.length) return `${franchise.name} has no players on its roster yet.`;
  const lines = rows.map((r) => {
    const total = r.appearances + r.credits;
    return `${String(r.display_name).slice(0, 20).padEnd(20)} ${String(total).padStart(2)}/${APPEARANCES_NEEDED}${r.credits ? ` (${r.credits} credit)` : ''} ${total >= APPEARANCES_NEEDED ? 'eligible' : `needs ${APPEARANCES_NEEDED - total}`}`;
  });
  return `**${franchise.name} · playoff eligibility · Season ${season}**\n\`\`\`\n${lines.join('\n')}\n\`\`\`\nGames played plus verified forfeit credits. Every player needs ${APPEARANCES_NEEDED} to play in the playoffs.`;
}

async function adminForfeit(interaction, env, opts) {
  const db = requireDb(env);
  const me = invokerId(interaction);
  const fixtureId = String(opts.fixture).trim();
  const fx = await db.prepare('SELECT * FROM fixtures WHERE fixture_id = ?').bind(fixtureId).first();
  if (!fx) return `No fixture \`${fixtureId}\`.`;
  if (fx.status === 'Final' || fx.status === 'Reported') {
    return `\`${fixtureId}\` is ${fx.status.toLowerCase()}. Resolve or reject its report first; forfeits can't overwrite a played result.`;
  }
  const both = opts.forfeiting === 'both';
  const winnerId = both ? null : opts.forfeiting === 'home' ? fx.away_id : fx.home_id;
  const resultType = both ? 'Double forfeit' : 'Forfeit';
  const now = nowIso();
  await db.batch([
    db.prepare("UPDATE fixtures SET status = 'Final', result_type = ?, winner_id = ?, home_score = NULL, away_score = NULL, updated_at = ? WHERE fixture_id = ?")
      .bind(resultType, winnerId, now, fixtureId),
    audit(db, me, 'fixtures', fixtureId, 'result_type', fx.result_type, resultType, opts.reason)
  ]);
  const [home, away] = await Promise.all([franchiseOf(db, fx.home_id), franchiseOf(db, fx.away_id)]);
  const text = both
    ? `**${fixtureId}** · double forfeit — ${home?.name} and ${away?.name} both take a loss.`
    : `**${fixtureId}** · ${(opts.forfeiting === 'home' ? home : away)?.name} forfeits — win to ${(opts.forfeiting === 'home' ? away : home)?.name}.`;
  try {
    await postToChannel(env, 'game-reports', { content: `${text}\nReason: ${opts.reason}${both ? '' : '\nReady players may request a playoff-eligibility credit with a locker-room screenshot.'}`, allowed_mentions: { parse: [] } });
  } catch (error) {
    console.error(`Forfeit post failed: ${error.message}`);
  }
  return `Recorded: ${text}`;
}

async function adminCredit(interaction, env, opts) {
  const db = requireDb(env);
  const me = invokerId(interaction);
  const fixtureId = String(opts.fixture).trim();
  const fx = await db.prepare('SELECT * FROM fixtures WHERE fixture_id = ?').bind(fixtureId).first();
  if (!fx || fx.result_type !== 'Forfeit') return `\`${fixtureId}\` isn't a single-team forfeit, so no credit applies (none for double forfeits).`;
  const player = await db.prepare('SELECT * FROM players WHERE discord_id = ?').bind(opts.player).first();
  if (!player) return 'That member isn\'t on a league roster.';
  if (player.franchise_id !== fx.winner_id) return `${player.display_name} isn't on the ready team for \`${fixtureId}\`.`;
  const existing = await db.prepare('SELECT 1 FROM eligibility_credits WHERE player_id = ? AND fixture_id = ?').bind(player.player_id, fixtureId).first();
  if (existing) return `${player.display_name} already has a credit for \`${fixtureId}\`.`;
  await db.batch([
    db.prepare('INSERT INTO eligibility_credits (player_id, fixture_id, granted_by, granted_at) VALUES (?, ?, ?, ?)').bind(player.player_id, fixtureId, me, nowIso()),
    audit(db, me, 'eligibility_credits', `${player.player_id}:${fixtureId}`, 'credit', null, 1, 'Ready-team forfeit credit verified')
  ]);
  return `Credit recorded for ${player.display_name} (\`${fixtureId}\`). It counts toward playoff eligibility only, not games played or stats.`;
}

const csvCell = (v) => {
  const text = v == null ? '' : String(v);
  return /[",\n]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text;
};
const toCsv = (header, rows) => [header.join(','), ...rows.map((r) => header.map((h) => csvCell(r[h])).join(','))].join('\n');

async function adminExport(env, opts) {
  const db = requireDb(env);
  const season = opts.season ?? await currentSeason(db);
  let text;
  if (opts.kind === 'standings') {
    const { fixtures, franchises } = await loadSeason(db, season);
    const rows = computeStandings(fixtures, franchises).map((r) => ({ ...r, pct: r.pct.toFixed(3), seed: r.seed ?? '', unresolved_tie: r.unresolvedTie ? 'yes' : '' }));
    text = toCsv(['rank', 'franchise_id', 'name', 'gp', 'w', 'l', 'pct', 'onCourt', 'forfeits', 'pf', 'pa', 'diff', 'remaining', 'seed', 'unresolved_tie'], rows);
  } else if (opts.kind === 'players') {
    const rows = (await playerSeasonStats(db, season)).map((r) => ({ ...r, efg: r.efg == null ? '' : r.efg.toFixed(3) }));
    text = toCsv(['player_id', 'display_name', 'franchise_id', 'gp', 'pts', 'reb', 'ast', 'stl', 'blk', 'tov', 'fgm', 'fga', 'tpm', 'tpa', 'ftm', 'fta', 'efg'], rows);
  } else {
    const rows = (await db.prepare(`
      SELECT f.season, f.week, pg.fixture_id, pg.player_id, p.display_name, pg.franchise_id, pg.pts, pg.reb, pg.ast, pg.stl, pg.blk, pg.tov,
        pg.fgm, pg.fga, pg.tpm, pg.tpa, pg.ftm, pg.fta, pg.fouls
      FROM player_games pg JOIN fixtures f ON f.fixture_id = pg.fixture_id LEFT JOIN players p ON p.player_id = pg.player_id
      WHERE f.season = ? AND f.status = 'Final' AND f.result_type = 'Played' ORDER BY f.week, pg.fixture_id, pg.franchise_id`).bind(season).all()).results ?? [];
    text = toCsv(['season', 'week', 'fixture_id', 'player_id', 'display_name', 'franchise_id', 'pts', 'reb', 'ast', 'stl', 'blk', 'tov', 'fgm', 'fga', 'tpm', 'tpa', 'ftm', 'fta', 'fouls'], rows);
  }
  const lines = text.split('\n').length - 1;
  return { content: `Season ${season} ${opts.kind} export: ${lines} row${lines === 1 ? '' : 's'}.`, file: { name: `season${season}-${opts.kind}.csv`, text } };
}

async function adminPublish(env, opts) {
  const db = requireDb(env);
  const season = opts.season ?? await currentSeason(db);
  const { fixtures, franchises } = await loadSeason(db, season);
  await postToChannel(env, 'standings', {
    content: `${formatStandings(computeStandings(fixtures, franchises), season)}\nUpdated <t:${unix(nowIso())}:f>`.slice(0, 1990),
    allowed_mentions: { parse: [] }
  });
  const stats = await playerSeasonStats(db, season);
  const names = Object.fromEntries(franchises.map((f) => [f.franchise_id, f.name]));
  const blocks = ['pts', 'reb', 'ast'].map((c) => formatLeaders(leaderList(stats, c).slice(0, 5), c, season, names));
  await postToChannel(env, 'league-stats', { content: blocks.join('\n').slice(0, 1990), allowed_mentions: { parse: [] } });
  return 'Posted standings in #standings and points/rebounds/assists leaders in #league-stats.';
}

// ---------------------------------------------------------------- contracts and FP (step 5)

const TIERS = {
  Franchise: { pcv: 18, band: [12, 16] },
  Star: { pcv: 15, band: [7, 11] },
  Core: { pcv: 12, band: [4, 6] },
  Rotation: { pcv: 8, band: [2, 4] },
  Development: { pcv: 5, band: [1, 2] }
};
const FP_CAP = 44;
const PCV_CAP = 90;
const PCV_FLOOR_PER_PLAYER = 7;
const MAX_FRANCHISE_TIER = 2;
const BANK_MAX = 22;
const ROSTER_MAX = 10;
const ROSTER_MIN = 8;
const MAX_YEARS = 3;

async function getSetting(db, key, fallback) {
  const row = await db.prepare('SELECT value FROM settings WHERE key = ?').bind(key).first();
  return row ? row.value : fallback;
}
async function leagueState(db) {
  const season = Number(await getSetting(db, 'season', null)) || await currentSeason(db);
  const phase = await getSetting(db, 'phase', 'offseason');
  return { season, phase };
}
const setSetting = (db, key, value) => db.prepare('INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value').bind(key, String(value));

const contractEnd = (c) => c.start_season + c.years - 1 + (c.option_status === 'Exercised' ? 1 : 0);
// Seasons a contract charges FP: active and dead-cap contracts through their end; bought-out ones stop.
const chargesIn = (c, y) => {
  if (y < c.start_season) return false;
  if (c.status === 'Active' || c.status === 'Dead cap') return y <= contractEnd(c);
  if (c.status === 'Bought out' || c.status === 'Expired' || c.status === 'Ended') return c.ended_season != null && y <= c.ended_season && y <= contractEnd(c);
  return false;
};
const onRosterIn = (c, y) => c.status === 'Active' && y >= c.start_season && y <= contractEnd(c);

// Pure roster check for one franchise's contracts, from `season` through every future contract year.
// allowedShortfall: how far under the floor the roster already was, so a move that doesn't make it worse is allowed.
function evaluateRoster(contracts, season, allowedShortfall = 0) {
  const roster = contracts.filter((c) => onRosterIn(c, season));
  const size = roster.length;
  const pcv = roster.reduce((n, c) => n + c.pcv, 0);
  const franchiseCount = roster.filter((c) => c.tier === 'Franchise').length;
  const lastYear = Math.max(season, ...contracts.map(contractEnd));
  const fp = {};
  for (let y = season; y <= lastYear; y += 1) fp[y] = contracts.filter((c) => chargesIn(c, y)).reduce((n, c) => n + c.fp_cost, 0);
  const problems = [];
  const warnings = [];
  if (size > ROSTER_MAX) problems.push(`${size} rostered players (maximum ${ROSTER_MAX})`);
  if (pcv > PCV_CAP) problems.push(`PCV ${pcv} is over the ${PCV_CAP} cap`);
  if (franchiseCount > MAX_FRANCHISE_TIER) problems.push(`${franchiseCount} Franchise-tier players (maximum ${MAX_FRANCHISE_TIER})`);
  const shortfall = size >= ROSTER_MIN ? Math.max(0, size * PCV_FLOOR_PER_PLAYER - pcv) : 0;
  if (shortfall > 0 && shortfall > allowedShortfall) problems.push(`PCV ${pcv} is under the ${size * PCV_FLOOR_PER_PLAYER} floor for ${size} players`);
  else if (shortfall > 0) warnings.push(`PCV ${pcv} is still under the ${size * PCV_FLOOR_PER_PLAYER} floor (no worse than before); fix it before the next game`);
  if (size < ROSTER_MIN && pcv < size * PCV_FLOOR_PER_PLAYER) warnings.push(`PCV ${pcv} would be under the floor (${size * PCV_FLOOR_PER_PLAYER}); the floor is enforced from ${ROSTER_MIN} players`);
  for (const [y, total] of Object.entries(fp)) if (total > FP_CAP) problems.push(`Season ${y} FP obligations ${total} are over ${FP_CAP}`);
  if (size < ROSTER_MIN) warnings.push(`${size} rostered players — at least ${ROSTER_MIN} are required before the first regular-season game`);
  return { size, pcv, floor: size * PCV_FLOOR_PER_PLAYER, shortfall, franchiseCount, fp, problems, warnings, legal: problems.length === 0 };
}

async function franchiseContracts(db, franchiseId) {
  return (await db.prepare("SELECT c.*, p.display_name FROM contracts c LEFT JOIN players p ON p.player_id = c.player_id WHERE c.franchise_id = ? AND c.status IN ('Active', 'Dead cap', 'Bought out')").bind(franchiseId).all()).results ?? [];
}

async function bankInfo(db, franchiseId, season) {
  const open = (await db.prepare('SELECT opening_balance FROM fp_bank WHERE franchise_id = ? AND season = ?').bind(franchiseId, season).first())?.opening_balance ?? 0;
  const spent = await db.prepare("SELECT COALESCE(SUM(from_current), 0) AS cur, COALESCE(SUM(from_bank), 0) AS bank FROM fp_ledger WHERE franchise_id = ? AND season = ? AND kind = 'buyout'").bind(franchiseId, season).first();
  return { opening: open, buyoutsFromCurrent: spent?.cur ?? 0, buyoutsFromBank: spent?.bank ?? 0, balance: open - (spent?.bank ?? 0) };
}

function checkText(result, season) {
  const fpText = Object.entries(result.fp).map(([y, v]) => `S${y} ${v}/${FP_CAP}`).join(' · ');
  return [
    `Players ${result.size}/${ROSTER_MAX} · Team value ${result.pcv}/${PCV_CAP} PCV${result.size >= ROSTER_MIN ? ` (minimum ${result.floor})` : ''} · Franchise-tier ${result.franchiseCount}/${MAX_FRANCHISE_TIER}`,
    `Salary used (FP): ${fpText || `S${season} 0/${FP_CAP}`}`,
    result.legal ? '✅ Within the rules' : `❌ Breaks the rules: ${result.problems.join('; ')}`,
    ...result.warnings.map((w) => `⚠️ ${w}`)
  ].join('\n');
}

async function capCommand(interaction, env, opts) {
  const db = requireDb(env);
  const { season, phase } = await leagueState(db);
  const franchiseId = opts.franchise ? String(opts.franchise).trim() : await myFranchiseId(db, invokerId(interaction));
  if (!franchiseId) return 'You aren\'t on a team.';
  const franchise = await franchiseOf(db, franchiseId);
  if (!franchise) return 'That team wasn\'t found.';
  const contracts = await franchiseContracts(db, franchiseId);
  const result = evaluateRoster(contracts, season);
  const bank = await bankInfo(db, franchiseId, season);
  const rows = contracts.filter((c) => onRosterIn(c, season) || (c.status === 'Active' && c.start_season > season))
    .sort((a, b) => b.pcv - a.pcv || b.fp_cost - a.fp_cost)
    .map((c) => `${String(c.display_name ?? c.player_id).slice(0, 16).padEnd(16)} ${c.tier.slice(0, 11).padEnd(11)} ${String(c.pcv).padStart(3)} ${String(c.fp_cost).padStart(3)}  S${c.start_season}–S${contractEnd(c)}${c.option_status === 'Pending' ? ' +opt' : ''}${c.start_season > season ? ' (next)' : ''}`);
  const dead = contracts.filter((c) => c.status === 'Dead cap' && contractEnd(c) >= season)
    .map((c) => `Released, still on the cap: ${c.display_name ?? c.player_id} ${c.fp_cost} FP/season through S${contractEnd(c)}`);
  return [
    `**${franchise.name} · Season ${season} (${phase === 'in-season' ? 'season in progress' : 'offseason'})**`,
    rows.length ? `\`\`\`\nPlayer           Tier        PCV  FP  Seasons\n${rows.join('\n')}\n\`\`\`` : 'No players signed yet.',
    ...dead,
    checkText(result, season),
    `Saved FP (bank): ${bank.balance}/${BANK_MAX}`
  ].join('\n').slice(0, 1990);
}

async function contractCommand(interaction, env, opts) {
  const db = requireDb(env);
  const target = opts.player ?? invokerId(interaction);
  const player = await db.prepare('SELECT * FROM players WHERE discord_id = ?').bind(target).first();
  if (!player) return 'That member isn\'t on a league roster.';
  const c = await db.prepare("SELECT * FROM contracts WHERE player_id = ? AND status = 'Active' ORDER BY start_season DESC LIMIT 1").bind(player.player_id).first();
  if (!c) return `**${player.display_name}** has no active contract (free agent).`;
  const franchise = await franchiseOf(db, c.franchise_id);
  return [
    `**${player.display_name}** · ${franchise?.name ?? c.franchise_id}`,
    `${c.tier} · ${c.pcv} PCV · ${c.fp_cost} FP per season (${c.fp_source})`,
    `Seasons ${c.start_season}–${contractEnd(c)}${c.option_status === 'Pending' ? ` · player option for season ${contractEnd(c) + 1} not yet decided` : c.option_status === 'Exercised' ? ' (includes exercised option year)' : c.option_status === 'Declined' ? ' · option declined' : ''}`,
    'PCV and FP cost are locked for the whole contract.'
  ].join('\n');
}

// ---- transactions: every change is previewed, then applied only when the Commissioner presses Approve.

async function proposeTransaction(env, db, me, kind, payload, preview) {
  const row = await db.prepare("INSERT INTO pending_tx (kind, payload, created_by, created_at, status) VALUES (?, ?, ?, ?, 'Pending') RETURNING id")
    .bind(kind, JSON.stringify(payload), me, nowIso()).first();
  return {
    content: `${preview}\n\nNothing has changed yet. Press **Approve** to record it, or **Cancel**.`.slice(0, 1990),
    components: [{
      type: 1,
      components: [
        { type: 2, style: 3, label: 'Approve', custom_id: `tx:approve:${row.id}` },
        { type: 2, style: 2, label: 'Cancel', custom_id: `tx:cancel:${row.id}` }
      ]
    }]
  };
}

async function playerByDiscord(db, discordId) {
  return db.prepare('SELECT * FROM players WHERE discord_id = ?').bind(discordId).first();
}
async function playerById(db, playerId) {
  return db.prepare('SELECT * FROM players WHERE player_id = ?').bind(playerId).first();
}
const findPlayer = (db, opts) => (opts.player_id ? playerById(db, opts.player_id) : playerByDiscord(db, opts.player));
async function activeContract(db, playerId) {
  return db.prepare("SELECT * FROM contracts WHERE player_id = ? AND status = 'Active' ORDER BY start_season DESC LIMIT 1").bind(playerId).first();
}

async function planSign(db, opts) {
  const { season, phase } = await leagueState(db);
  const player = await findPlayer(db, opts);
  if (!player) return { error: 'That member isn\'t in the player list yet. Add them with `/drew admin player` first.' };
  const franchise = await franchiseOf(db, String(opts.franchise).trim());
  if (!franchise) return { error: `No franchise \`${opts.franchise}\`.` };
  const tier = TIERS[opts.tier];
  if (!tier) return { error: 'Choose a tier.' };
  if (opts.fp_cost < tier.band[0] || opts.fp_cost > tier.band[1]) return { error: `${opts.tier} FP cost must be ${tier.band[0]}–${tier.band[1]}.` };
  if (opts.player_option && opts.years >= MAX_YEARS) return { error: `A player option can only be added to a 1- or 2-season contract (maximum ${MAX_YEARS} seasons in total).` };
  const existing = await activeContract(db, player.player_id);
  // Signing in the offseason starts with the upcoming season; once the season starts, it starts now.
  const startSeason = season;
  if (existing && contractEnd(existing) >= startSeason) {
    const owner = await franchiseOf(db, existing.franchise_id);
    return { error: `${player.display_name} is under contract with ${owner?.name ?? existing.franchise_id} through season ${contractEnd(existing)}.` };
  }
  const contract = {
    player_id: player.player_id, franchise_id: franchise.franchise_id, tier: opts.tier, pcv: tier.pcv, fp_cost: opts.fp_cost,
    fp_source: opts.source, start_season: startSeason, years: opts.years, option_status: opts.player_option ? 'Pending' : 'None', status: 'Active'
  };
  const current = await franchiseContracts(db, franchise.franchise_id);
  const result = evaluateRoster([...current, contract], season, evaluateRoster(current, season).shortfall);
  return { player, franchise, contract, result, season, phase };
}

async function adminSign(interaction, env, opts) {
  const db = requireDb(env);
  const plan = await planSign(db, opts);
  if (plan.error) return plan.error;
  const { player, franchise, contract, result, season } = plan;
  const preview = [
    `**Signing preview** — ${player.display_name} (${player.player_id}) to **${franchise.name}**`,
    `${contract.tier} · ${contract.pcv} PCV · ${contract.fp_cost} FP/season (${contract.fp_source}) · seasons ${contract.start_season}–${contractEnd(contract)}${contract.option_status === 'Pending' ? ` + player option for season ${contractEnd(contract) + 1}` : ''}`,
    `**${franchise.name} after this signing:**`,
    checkText(result, season),
    contract.option_status === 'Pending' ? 'Confirm the player has 3 full seasons with this franchise before approving the option.' : null
  ].filter(Boolean).join('\n');
  if (!result.legal) return `${preview}\n\nThis signing would make the roster illegal, so it can't be recorded.`;
  return proposeTransaction(env, db, invokerId(interaction), 'sign', opts, preview);
}

async function planRelease(db, opts) {
  const { season, phase } = await leagueState(db);
  const player = await findPlayer(db, opts);
  if (!player) return { error: 'That member isn\'t on a league roster.' };
  const contract = await activeContract(db, player.player_id);
  if (!contract) return { error: `${player.display_name} has no active contract.` };
  const franchise = await franchiseOf(db, contract.franchise_id);
  const lastGuaranteed = contract.start_season + contract.years - 1 + (contract.option_status === 'Exercised' ? 1 : 0);
  if (opts.method === 'buyout') {
    if (phase !== 'offseason') return { error: 'Buyouts are only allowed in the offseason. Release with the salary staying on the cap, or wait for the season to close.' };
    const firstUnpaid = Math.max(season, contract.start_season);
    const seasonsLeft = Math.max(0, lastGuaranteed - firstUnpaid + 1);
    const cost = Math.ceil((contract.fp_cost * seasonsLeft) / 2);
    const others = (await franchiseContracts(db, contract.franchise_id)).filter((c) => c.contract_id !== contract.contract_id);
    const obligations = others.filter((c) => chargesIn(c, season)).reduce((n, c) => n + c.fp_cost, 0);
    const bank = await bankInfo(db, contract.franchise_id, season);
    const currentAvailable = Math.max(0, FP_CAP - obligations - bank.buyoutsFromCurrent);
    const fromCurrent = Math.min(cost, currentAvailable);
    const fromBank = cost - fromCurrent;
    if (fromBank > bank.balance) {
      return { error: `The buyout costs ${cost} FP (half of ${contract.fp_cost} × ${seasonsLeft} remaining seasons, rounded up), but ${franchise?.name} only has ${currentAvailable} unused this season plus ${bank.balance} saved. Release with the salary staying on the cap instead.` };
    }
    return { player, contract, franchise, season, cost, fromCurrent, fromBank, seasonsLeft, firstUnpaid };
  }
  return { player, contract, franchise, season, lastGuaranteed };
}

async function adminRelease(interaction, env, opts) {
  const db = requireDb(env);
  const plan = await planRelease(db, opts);
  if (plan.error) return plan.error;
  const { player, contract, franchise } = plan;
  const preview = opts.method === 'buyout'
    ? `**Buyout preview** — ${player.display_name} from **${franchise?.name}**\nCost ${plan.cost} FP: ${plan.fromCurrent} from this season's unused FP and ${plan.fromBank} from the bank. The contract ends and its future FP comes off the cap. The player becomes a free agent.\nReason: ${opts.reason}`
    : `**Dead-cap release preview** — ${player.display_name} from **${franchise?.name}**\nThe player leaves the roster and becomes a free agent, but ${contract.fp_cost} FP per season stays on ${franchise?.name}'s cap through season ${plan.lastGuaranteed}.\nReason: ${opts.reason}`;
  return proposeTransaction(env, db, invokerId(interaction), 'release', opts, preview);
}

function parseIds(text) {
  return String(text ?? '').split(/[\s,]+/).map((x) => x.trim()).filter(Boolean);
}

async function planTrade(db, opts) {
  const { season } = await leagueState(db);
  const a = await franchiseOf(db, String(opts.franchise_a).trim());
  const b = await franchiseOf(db, String(opts.franchise_b).trim());
  if (!a || !b) return { error: 'Check both franchise IDs.' };
  if (a.franchise_id === b.franchise_id) return { error: 'A trade needs two different franchises.' };
  const idsA = parseIds(opts.players_a);
  const idsB = parseIds(opts.players_b);
  if (!idsA.length && !idsB.length) return { error: 'List at least one player.' };
  const moving = [];
  for (const [ids, from] of [[idsA, a], [idsB, b]]) {
    for (const id of ids) {
      const c = await activeContract(db, id);
      if (!c || c.franchise_id !== from.franchise_id) return { error: `${id} doesn't have an active contract with ${from.name}.` };
      moving.push({ ...c, to: from === a ? b.franchise_id : a.franchise_id });
    }
  }
  const after = async (f) => {
    const all = await franchiseContracts(db, f.franchise_id);
    const mine = all.filter((c) => !moving.some((m) => m.contract_id === c.contract_id));
    return evaluateRoster([...mine, ...moving.filter((m) => m.to === f.franchise_id).map((m) => ({ ...m, franchise_id: f.franchise_id }))], season, evaluateRoster(all, season).shortfall);
  };
  return { a, b, moving, season, resultA: await after(a), resultB: await after(b) };
}

async function adminTrade(interaction, env, opts) {
  const db = requireDb(env);
  const plan = await planTrade(db, opts);
  if (plan.error) return plan.error;
  const { a, b, moving, season, resultA, resultB } = plan;
  const names = async (list) => (await Promise.all(list.map(async (m) => (await db.prepare('SELECT display_name FROM players WHERE player_id = ?').bind(m.player_id).first())?.display_name ?? m.player_id))).join(', ') || 'nobody';
  const preview = [
    '**Trade preview**',
    `${a.name} sends: ${await names(moving.filter((m) => m.to === b.franchise_id))}`,
    `${b.name} sends: ${await names(moving.filter((m) => m.to === a.franchise_id))}`,
    'Contracts move as they are: tier, PCV, FP cost, remaining seasons, and option terms. No FP changes hands.',
    `**${a.name} after:**\n${checkText(resultA, season)}`,
    `**${b.name} after:**\n${checkText(resultB, season)}`,
    'Before approving, confirm both GMs agreed and every traded player consented (the Commissioner handles a GM-player\'s side).'
  ].join('\n');
  if (!resultA.legal || !resultB.legal) return `${preview}\n\nThis trade would make a roster illegal, so it can't be recorded.`;
  return proposeTransaction(env, db, invokerId(interaction), 'trade', opts, preview);
}

async function planOption(db, opts) {
  const { season } = await leagueState(db);
  const player = await playerByDiscord(db, opts.player);
  if (!player) return { error: 'That member isn\'t on a league roster.' };
  const contract = await activeContract(db, player.player_id);
  if (!contract || contract.option_status !== 'Pending') return { error: `${player.display_name} has no undecided player option.` };
  const franchise = await franchiseOf(db, contract.franchise_id);
  const result = opts.decision === 'exercise'
    ? evaluateRoster((await franchiseContracts(db, contract.franchise_id)).map((c) => (c.contract_id === contract.contract_id ? { ...c, option_status: 'Exercised' } : c)), season)
    : null;
  return { player, contract, franchise, result, season };
}

async function adminOption(interaction, env, opts) {
  const db = requireDb(env);
  const plan = await planOption(db, opts);
  if (plan.error) return plan.error;
  const { player, contract, franchise, result, season } = plan;
  const preview = opts.decision === 'exercise'
    ? `**Option preview** — ${player.display_name} exercises the option: contract extends to season ${contractEnd(contract) + 1} at ${contract.fp_cost} FP.\n**${franchise?.name} after:**\n${checkText(result, season)}${result.legal ? '' : "\nThe player's choice stands; the franchise must fix its roster before its next game."}`
    : `**Option preview** — ${player.display_name} declines the option and becomes a free agent after season ${contractEnd(contract)}.`;
  return proposeTransaction(env, db, invokerId(interaction), 'option', opts, preview);
}

async function planSeasonClose(db) {
  const { season, phase } = await leagueState(db);
  const contracts = (await db.prepare("SELECT c.*, p.display_name FROM contracts c LEFT JOIN players p ON p.player_id = c.player_id WHERE c.status IN ('Active', 'Dead cap')").all()).results ?? [];
  const undecided = contracts.filter((c) => c.status === 'Active' && c.option_status === 'Pending' && contractEnd(c) === season);
  const franchises = (await db.prepare('SELECT * FROM franchises ORDER BY name').all()).results ?? [];
  const banks = [];
  for (const f of franchises) {
    const all = await franchiseContracts(db, f.franchise_id);
    const obligations = all.filter((c) => chargesIn(c, season)).reduce((n, c) => n + c.fp_cost, 0);
    const bank = await bankInfo(db, f.franchise_id, season);
    const unused = Math.max(0, FP_CAP - obligations - bank.buyoutsFromCurrent);
    banks.push({ franchise: f, obligations, unused, next: Math.min(BANK_MAX, bank.balance + unused), expiresOver: Math.max(0, bank.balance + unused - BANK_MAX) });
  }
  const expiring = contracts.filter((c) => contractEnd(c) === season && !(c.option_status === 'Pending'));
  return { season, phase, undecided, banks, expiring };
}

async function adminSeason(interaction, env, opts) {
  const db = requireDb(env);
  const { season, phase } = await leagueState(db);
  if (opts.action === 'start') {
    if (phase === 'in-season') return `Season ${season} has already started.`;
    const illegal = [];
    for (const f of (await db.prepare('SELECT * FROM franchises ORDER BY name').all()).results ?? []) {
      const r = evaluateRoster(await franchiseContracts(db, f.franchise_id), season);
      if (!r.legal || r.size < ROSTER_MIN) illegal.push(`${f.name}: ${[...r.problems, ...(r.size < ROSTER_MIN ? [`only ${r.size} players`] : [])].join('; ')}`);
    }
    const preview = `**Start season ${season}** — FP obligations for season ${season} are charged and buyouts close until the season ends.${illegal.length ? `\n⚠️ Not ready:\n${illegal.join('\n')}` : '\nEvery franchise has a legal roster of at least 8.'}`;
    return proposeTransaction(env, db, invokerId(interaction), 'season', opts, preview);
  }
  if (phase !== 'in-season') return `Season ${season} hasn't started, so it can't be closed. Use \`start\` first.`;
  const plan = await planSeasonClose(db);
  if (plan.undecided.length) return `Can't close yet: these player options for season ${season + 1} are undecided: ${plan.undecided.map((c) => c.display_name ?? c.player_id).join(', ')}. Record them with \`/drew admin option\`.`;
  const preview = [
    `**Close season ${season}**`,
    `Expiring contracts (players become free agents): ${plan.expiring.filter((c) => c.status === 'Active').map((c) => c.display_name ?? c.player_id).join(', ') || 'none'}`,
    'Banked FP for next season (unused this season, capped at 22):',
    ...plan.banks.map((b) => `• ${b.franchise.name}: used ${b.obligations}/${FP_CAP}, unused ${b.unused} → bank ${b.next}${b.expiresOver ? ` (${b.expiresOver} expires)` : ''}`),
    `The league moves to season ${season + 1} offseason.`
  ].join('\n');
  return proposeTransaction(env, db, invokerId(interaction), 'season', opts, preview);
}

async function announce(env, text) {
  try {
    await postToChannel(env, 'transactions', { content: text.slice(0, 1990), allowed_mentions: { parse: [] } });
  } catch (error) {
    console.error(`Transaction post failed: ${error.message}`);
  }
}

async function recordSigning(env, db, plan, me, note) {
  const c = plan.contract;
  const now = nowIso();
  const row = await db.prepare('INSERT INTO contracts (player_id, franchise_id, tier, pcv, fp_cost, fp_source, start_season, years, option_status, status, signed_at, signed_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING contract_id')
    .bind(c.player_id, c.franchise_id, c.tier, c.pcv, c.fp_cost, c.fp_source, c.start_season, c.years, c.option_status, 'Active', now, me).first();
  await db.batch([
    db.prepare('UPDATE players SET franchise_id = ?, updated_at = ? WHERE player_id = ?').bind(c.franchise_id, now, c.player_id),
    audit(db, me, 'contracts', row.contract_id, 'signed', null, JSON.stringify(c), note)
  ]);
  await announce(env, `**Signing** · ${plan.player.display_name} → **${plan.franchise.name}** · ${c.tier} · ${c.fp_cost} FP per season · ${c.years} season${c.years > 1 ? 's' : ''} (through season ${contractEnd(c)})${c.option_status === 'Pending' ? ' + option year' : ''}`);
  return row.contract_id;
}

// Re-check and apply an approved transaction. Returns the text for the preview message.
async function applyTransaction(env, db, tx, me) {
  const opts = JSON.parse(tx.payload);
  const now = nowIso();
  if (tx.kind === 'sign') {
    const plan = await planSign(db, opts);
    if (plan.error) return `Not recorded: ${plan.error}`;
    if (!plan.result.legal) return `Not recorded: the roster changed and this signing is no longer legal (${plan.result.problems.join('; ')}).`;
    await recordSigning(env, db, plan, me, `Pending transaction #${tx.id}`);
    return `Recorded: ${plan.player.display_name} signed with ${plan.franchise.name}.`;
  }
  if (tx.kind === 'release') {
    const plan = await planRelease(db, opts);
    if (plan.error) return `Not recorded: ${plan.error}`;
    const { contract, player, franchise, season } = plan;
    const statements = [db.prepare('UPDATE players SET franchise_id = NULL, updated_at = ? WHERE player_id = ?').bind(now, player.player_id)];
    if (opts.method === 'buyout') {
      statements.push(db.prepare("UPDATE contracts SET status = 'Bought out', ended_season = ?, ended_at = ? WHERE contract_id = ?").bind(plan.firstUnpaid - 1, now, contract.contract_id));
      statements.push(db.prepare("INSERT INTO fp_ledger (franchise_id, season, kind, amount, from_current, from_bank, note, at) VALUES (?, ?, 'buyout', ?, ?, ?, ?, ?)")
        .bind(contract.franchise_id, season, plan.cost, plan.fromCurrent, plan.fromBank, `Buyout of ${player.player_id}`, now));
    } else {
      statements.push(db.prepare("UPDATE contracts SET status = 'Dead cap', ended_at = ? WHERE contract_id = ?").bind(now, contract.contract_id));
    }
    statements.push(audit(db, me, 'contracts', contract.contract_id, 'status', 'Active', opts.method === 'buyout' ? 'Bought out' : 'Dead cap', opts.reason));
    await db.batch(statements);
    await announce(env, opts.method === 'buyout'
      ? `**Buyout** · ${franchise?.name} releases ${player.display_name} for ${plan.cost} FP. ${player.display_name} is a free agent.`
      : `**Release** · ${franchise?.name} releases ${player.display_name}; ${contract.fp_cost} FP per season stays on their cap through season ${plan.lastGuaranteed}. ${player.display_name} is a free agent.`);
    return `Recorded: ${player.display_name} released (${opts.method === 'buyout' ? `buyout ${plan.cost} FP` : 'dead cap'}).`;
  }
  if (tx.kind === 'trade') {
    const plan = await planTrade(db, opts);
    if (plan.error) return `Not recorded: ${plan.error}`;
    if (!plan.resultA.legal || !plan.resultB.legal) return 'Not recorded: the rosters changed and this trade is no longer legal.';
    const statements = [];
    for (const m of plan.moving) {
      statements.push(db.prepare('UPDATE contracts SET franchise_id = ? WHERE contract_id = ?').bind(m.to, m.contract_id));
      statements.push(db.prepare('UPDATE players SET franchise_id = ?, updated_at = ? WHERE player_id = ?').bind(m.to, now, m.player_id));
      statements.push(audit(db, me, 'contracts', m.contract_id, 'franchise_id', m.franchise_id, m.to, `Trade, pending transaction #${tx.id}`));
    }
    await db.batch(statements);
    const label = async (to) => (await Promise.all(plan.moving.filter((m) => m.to === to).map(async (m) => (await db.prepare('SELECT display_name FROM players WHERE player_id = ?').bind(m.player_id).first())?.display_name ?? m.player_id))).join(', ') || 'nobody';
    await announce(env, `**Trade** · ${plan.a.name} receive ${await label(plan.a.franchise_id)} · ${plan.b.name} receive ${await label(plan.b.franchise_id)}`);
    return 'Recorded: trade completed.';
  }
  if (tx.kind === 'option') {
    const plan = await planOption(db, opts);
    if (plan.error) return `Not recorded: ${plan.error}`;
    const status = opts.decision === 'exercise' ? 'Exercised' : 'Declined';
    await db.batch([
      db.prepare('UPDATE contracts SET option_status = ? WHERE contract_id = ?').bind(status, plan.contract.contract_id),
      audit(db, me, 'contracts', plan.contract.contract_id, 'option_status', 'Pending', status, null)
    ]);
    await announce(env, `**Player option** · ${plan.player.display_name} ${status.toLowerCase()} the option with ${plan.franchise?.name}.`);
    return `Recorded: option ${status.toLowerCase()}.`;
  }
  if (tx.kind === 'season') {
    const { season, phase } = await leagueState(db);
    if (opts.action === 'start') {
      if (phase === 'in-season') return 'Not recorded: the season already started.';
      await db.batch([setSetting(db, 'season', season), setSetting(db, 'phase', 'in-season'), audit(db, me, 'settings', 'phase', phase, 'in-season', `Season ${season} started`)]);
      await announce(env, `**Season ${season} has started.** FP obligations are charged and buyouts are closed until the season ends.`);
      return `Recorded: season ${season} started.`;
    }
    if (phase !== 'in-season') return 'Not recorded: the season isn\'t in progress.';
    const plan = await planSeasonClose(db);
    if (plan.undecided.length) return 'Not recorded: player options are still undecided.';
    const statements = [];
    for (const b of plan.banks) {
      statements.push(db.prepare('INSERT INTO fp_bank (franchise_id, season, opening_balance) VALUES (?, ?, ?) ON CONFLICT(franchise_id, season) DO UPDATE SET opening_balance = excluded.opening_balance').bind(b.franchise.franchise_id, season + 1, b.next));
    }
    for (const c of plan.expiring) {
      statements.push(db.prepare("UPDATE contracts SET status = ?, ended_season = ?, ended_at = ? WHERE contract_id = ?").bind(c.status === 'Active' ? 'Expired' : 'Ended', season, now, c.contract_id));
      if (c.status === 'Active') statements.push(db.prepare('UPDATE players SET franchise_id = NULL, updated_at = ? WHERE player_id = ? AND franchise_id = ?').bind(now, c.player_id, c.franchise_id));
    }
    statements.push(setSetting(db, 'season', season + 1), setSetting(db, 'phase', 'offseason'));
    statements.push(audit(db, me, 'settings', 'season', season, season + 1, `Season ${season} closed`));
    await db.batch(statements);
    await announce(env, `**Season ${season} is closed.** ${plan.expiring.filter((c) => c.status === 'Active').length} contracts expired and those players are free agents. Season ${season + 1} offseason is open.`);
    return `Recorded: season ${season} closed; now in the season ${season + 1} offseason.`;
  }
  return 'Unknown transaction.';
}

async function transactionButton(interaction, env, action, txId) {
  const db = requireDb(env);
  const me = invokerId(interaction);
  if (!isCommissioner(await memberRoleNames(interaction, env))) {
    await followUp(interaction, 'Only the Commissioner can approve or turn down these.');
    return;
  }
  const tx = await db.prepare('SELECT * FROM pending_tx WHERE id = ?').bind(txId).first();
  if (!tx || tx.status !== 'Pending') {
    await editOriginal(interaction, { components: [] });
    await followUp(interaction, 'This transaction was already handled.');
    return;
  }
  const claimed = await db.prepare("UPDATE pending_tx SET status = 'Processing', decided_by = ?, decided_at = ? WHERE id = ? AND status = 'Pending' RETURNING id").bind(me, nowIso(), txId).first();
  if (!claimed) return;
  const original = interaction.message?.content?.replace(/\n\nNothing has changed yet\.[\s\S]*$/, '') ?? '';
  const tell = async (text) => { if (tx.created_by && tx.created_by !== me) await dmUser(env, tx.created_by, text); };
  if (action === 'cancel') {
    await db.prepare("UPDATE pending_tx SET status = 'Cancelled' WHERE id = ?").bind(txId).run();
    await editOriginal(interaction, { content: `${original}\n\n**Turned down.** Nothing was changed.`.slice(0, 1990), components: [] });
    await tell(`The Commissioner turned down your ${tx.kind} request (#${txId}). Nothing was changed.`);
    return;
  }
  const result = await applyTransaction(env, db, tx, me);
  await db.prepare('UPDATE pending_tx SET status = ? WHERE id = ?').bind(result.startsWith('Recorded') ? 'Applied' : 'Failed', txId).run();
  await editOriginal(interaction, { content: `${original}\n\n**${result}**`.slice(0, 1990), components: [] });
  await tell(`Your ${tx.kind} request (#${txId}): ${result}`);
}

// ---------------------------------------------------------------- league menu (buttons first)
// Players and GMs tap buttons and pick from lists; nobody types IDs or commands.
// Replies are private (only the person who tapped sees them).

const ZONE_ABBR = { eastern: 'ET', central: 'CT', mountain: 'MT', arizona: 'AZ', pacific: 'PT', utc: 'UTC' };
const TIER_ORDER = ['Franchise', 'Star', 'Core', 'Rotation', 'Development'];
const btn = (label, customId, style = 2, disabled = false) => ({ type: 2, style, label: String(label).slice(0, 80), custom_id: customId, ...(disabled ? { disabled: true } : {}) });
const actionRow = (...components) => ({ type: 1, components });
function stringSelect(customId, placeholder, options, { min = 1, max = 1 } = {}) {
  const list = options.slice(0, 25);
  return { type: 3, custom_id: customId, placeholder: placeholder.slice(0, 150), options: list, min_values: Math.min(min, list.length), max_values: Math.max(1, Math.min(max, list.length)) };
}
const GM_ONLY = 'GM tools are for team GMs. If you are a GM and see this, ask the Commissioner to set you as your team\'s GM.';

// Values from a submitted pop-up form, keyed by custom_id (text = string, lists and files = array).
function modalValues(interaction) {
  const out = {};
  const walk = (list) => {
    for (const c of list ?? []) {
      if (c.component) walk([c.component]);
      if (c.components) walk(c.components);
      if (c.custom_id) out[c.custom_id] = c.values ?? c.value;
    }
  };
  walk(interaction.data?.components);
  return out;
}

// Acknowledge a tap inside a private message, then replace that message with the result.
function deferUpdate(ctx, interaction, work) {
  ctx.waitUntil((async () => {
    let out;
    try {
      out = await work();
    } catch (error) {
      console.error(`Menu step failed: ${error.message}`);
      out = 'Something went wrong on DREW\'s side. Nothing was changed unless a message above says so. Try again, or contact the Commissioner.';
    }
    if (out == null) return;
    await editOriginal(interaction, typeof out === 'string' ? { content: out, components: [] } : { components: [], ...out });
  })());
  return json({ type: 6 });
}

const fromPrivateMessage = (interaction) => Boolean((interaction.message?.flags ?? 0) & EPHEMERAL);
// Taps on a public message (the pinned menu, the draft board) get a new private reply;
// taps inside a private reply update that reply in place.
const respond = (ctx, interaction, work) => (fromPrivateMessage(interaction) ? deferUpdate : deferEphemeral)(ctx, interaction, work);

async function dmUser(env, userId, content) {
  if (!userId || !env.DISCORD_BOT_TOKEN) return false;
  try {
    const channel = await discordApi('POST', '/users/@me/channels', env.DISCORD_BOT_TOKEN, { recipient_id: userId });
    await discordApi('POST', `/channels/${channel.id}/messages`, env.DISCORD_BOT_TOKEN, { content: content.slice(0, 1990), allowed_mentions: { parse: [] } });
    return true;
  } catch (error) {
    console.error(`Direct message failed: ${error.message}`);
    return false;
  }
}

async function userZone(db, discordId) {
  const zone = await getSetting(db, `tz:${discordId}`, 'eastern');
  return TIMEZONES[zone] ? zone : 'eastern';
}

function localLabel(iso, zoneKey) {
  return `${new Intl.DateTimeFormat('en-US', { timeZone: TIMEZONES[zoneKey], weekday: 'short', month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit' }).format(new Date(iso))} ${ZONE_ABBR[zoneKey]}`;
}

function dayOptions(zoneKey, count = 21) {
  const timeZone = TIMEZONES[zoneKey];
  const value = new Intl.DateTimeFormat('en-CA', { timeZone, year: 'numeric', month: '2-digit', day: '2-digit' });
  const label = new Intl.DateTimeFormat('en-US', { timeZone, weekday: 'short', month: 'short', day: 'numeric' });
  const today = value.format(new Date());
  const seen = new Set();
  const out = [];
  for (let i = -1; out.length < count && i < count + 2; i += 1) {
    const d = new Date(Date.now() + i * 86400000);
    const v = value.format(d);
    if (seen.has(v)) continue;
    seen.add(v);
    out.push({ label: `${label.format(d)}${v === today ? ' (today)' : ''}`, value: v, ...(v === today ? { default: true } : {}) });
  }
  return out;
}

const MENU_TEXT = '**League menu** — tap a button. Only you see DREW\'s answers.';
function menuComponents() {
  return [
    actionRow(btn('Report a game', 'menu:report', 1), btn('My games', 'menu:games'), btn('Set a game time', 'menu:time')),
    actionRow(btn('My stats', 'menu:stats'), btn('My team', 'menu:team'), btn('Standings', 'menu:standings'), btn('League leaders', 'menu:leaders')),
    actionRow(btn('Link my gamertag', 'menu:gamertag'), btn('Offers & requests', 'menu:offers'), btn('GM tools', 'menu:gm'), btn('Draft', 'menu:draft'), btn('How it works', 'menu:help'))
  ];
}
const menuMessage = () => ({ content: MENU_TEXT, components: menuComponents() });

// ---- picking a game from a list

async function gamesWithNames(db, whereSql, binds) {
  return (await db.prepare(
    `SELECT f.*, COALESCE(h.name, f.home_id) AS home_name, COALESCE(a.name, f.away_id) AS away_name FROM fixtures f
     LEFT JOIN franchises h ON h.franchise_id = f.home_id LEFT JOIN franchises a ON a.franchise_id = f.away_id
     WHERE ${whereSql} ORDER BY f.season, f.week, f.fixture_id`
  ).bind(...binds).all()).results ?? [];
}

async function gameWithNames(db, fixtureId) {
  return (await gamesWithNames(db, 'f.fixture_id = ?', [fixtureId]))[0] ?? null;
}

// Games a captain or GM can report now: open games plus no-report wins still in the 48-hour fix window.
async function reportableGames(db, me) {
  const staff = (await staffFranchises(db, me)).map((f) => f.franchise_id);
  if (!staff.length) return { staff, games: [] };
  const marks = staff.map(() => '?').join(', ');
  const rows = await gamesWithNames(db, `(f.home_id IN (${marks}) OR f.away_id IN (${marks})) AND f.status IN ('Scheduled', 'Time proposed', 'Time set', 'Unreported')`, [...staff, ...staff]);
  const now = Date.now();
  const rank = (fx) => (fx.status === 'Unreported' || (fx.agreed_start_utc && Date.parse(fx.agreed_start_utc) <= now) ? 0
    : fx.agreed_start_utc ? 1 : fx.status === 'Time proposed' ? 2 : 3);
  const games = rows
    .filter((fx) => fx.status !== 'Unreported' || now - Date.parse(fx.unreported_at ?? fx.updated_at) <= CORRECTION_WINDOW_MS)
    .sort((a, b) => rank(a) - rank(b) || a.season - b.season || a.week - b.week);
  return { staff, games };
}

function gameOption(fx, zone, staff = []) {
  const mineHome = staff.includes(fx.home_id);
  const when = fx.status === 'Unreported' ? 'No report yet: home team has the win for now'
    : fx.agreed_start_utc ? localLabel(fx.agreed_start_utc, zone)
      : fx.proposed_start_utc ? `Suggested ${localLabel(fx.proposed_start_utc, zone)}` : 'No time set';
  return {
    label: `Week ${fx.week}: ${fx.home_name} vs ${fx.away_name}`.slice(0, 100),
    value: fx.fixture_id,
    description: `${staff.length ? (mineHome ? 'Your home game · ' : 'Away game · ') : ''}${when}`.slice(0, 100)
  };
}

async function menuReport(interaction, env) {
  const db = requireDb(env);
  const me = invokerId(interaction);
  const { staff, games } = await reportableGames(db, me);
  if (!staff.length) return 'Only a team\'s captain or GM reports games. If your team won, ask your captain or GM to report it.';
  if (!games.length) return 'Your team has no games waiting for a report.';
  const zone = await userZone(db, me);
  return {
    content: '**Report a game** · Pick the game. Next you\'ll choose who won and upload the screenshot.\nOnly the winning team reports.',
    components: [actionRow(stringSelect('rpt:pick', 'Choose the game', games.map((fx) => gameOption(fx, zone, staff))))]
  };
}

function reportModal(fx) {
  return json({
    type: 9,
    data: {
      custom_id: `rptform:${fx.fixture_id}`,
      title: 'Report a game',
      components: [
        { type: 10, content: `Week ${fx.week} · **${fx.home_name}** (home) vs **${fx.away_name}**\nUpload the Game Stats screen that shows both teams.` },
        {
          type: 18, label: 'Who won?',
          component: { type: 3, custom_id: 'winner', placeholder: 'Pick the winning team', min_values: 1, max_values: 1, options: [{ label: String(fx.home_name).slice(0, 100), value: fx.home_id }, { label: String(fx.away_name).slice(0, 100), value: fx.away_id }] }
        },
        {
          type: 18, label: 'Box-score screenshot', description: 'The Game Stats screen with both teams visible',
          component: { type: 19, custom_id: 'shot', min_values: 1, max_values: 1, required: true }
        }
      ]
    }
  });
}

async function menuGameTime(interaction, env) {
  const db = requireDb(env);
  const me = invokerId(interaction);
  let staff = (await staffFranchises(db, me)).map((f) => f.franchise_id);
  let rows;
  if (staff.length) {
    const marks = staff.map(() => '?').join(', ');
    rows = await gamesWithNames(db, `(f.home_id IN (${marks}) OR f.away_id IN (${marks})) AND f.status IN ('Scheduled', 'Time proposed', 'Time set')`, [...staff, ...staff]);
  } else if (isCommissioner(await memberRoleNames(interaction, env))) {
    rows = await gamesWithNames(db, "f.status IN ('Scheduled', 'Time proposed', 'Time set')", []);
    staff = [];
  } else {
    return 'Only a team\'s captain or GM sets game times.';
  }
  const now = Date.now();
  rows = rows.filter((fx) => !fx.agreed_start_utc || Date.parse(fx.agreed_start_utc) > now);
  if (!rows.length) return 'No games need a time right now.';
  const zone = await userZone(db, me);
  return {
    content: '**Set a game time** · Pick the game. Next you\'ll choose the day and time; the other team confirms it.',
    components: [actionRow(stringSelect('gt:pick', 'Choose the game', rows.map((fx) => gameOption(fx, zone, staff))))]
  };
}

function gameTimeModal(fx, zone) {
  return json({
    type: 9,
    data: {
      custom_id: `gtform:${fx.fixture_id}`,
      title: 'Set the game time',
      components: [
        { type: 10, content: `Week ${fx.week} · **${fx.home_name}** (home) vs **${fx.away_name}**\nThe other team confirms it. The winner then has 24 hours from this time to report.` },
        { type: 18, label: 'Day', component: { type: 3, custom_id: 'day', placeholder: 'Pick the day', min_values: 1, max_values: 1, options: dayOptions(zone) } },
        { type: 18, label: 'Start time', description: 'For example 8:30 PM or 20:30', component: { type: 4, custom_id: 'time', style: 1, min_length: 1, max_length: 8, placeholder: '8:30 PM', required: true } },
        {
          type: 18, label: 'Your time zone',
          component: { type: 3, custom_id: 'tz', min_values: 1, max_values: 1, options: TIMEZONE_CHOICES.map((z) => ({ label: z.name, value: z.value, ...(z.value === zone ? { default: true } : {}) })) }
        }
      ]
    }
  });
}

async function gameTimeFromForm(interaction, env, fixtureId) {
  const db = requireDb(env);
  const v = modalValues(interaction);
  const zone = TIMEZONES[v.tz?.[0]] ? v.tz[0] : 'eastern';
  await setSetting(db, `tz:${invokerId(interaction)}`, zone).run();
  return gameTime(interaction, env, { fixture: fixtureId, date: v.day?.[0], time: v.time, timezone: zone });
}

async function gamertagModal(env, interaction) {
  const db = requireDb(env);
  const rows = (await db.prepare("SELECT * FROM gamertags WHERE discord_id = ? AND status IN ('Approved', 'Pending') ORDER BY id DESC").bind(invokerId(interaction)).all()).results ?? [];
  const approved = rows.find((r) => r.status === 'Approved');
  const pending = rows.find((r) => r.status === 'Pending');
  const status = [
    approved ? `Linked now: **${approved.gamertag}** (${approved.platform})` : 'No gamertag linked yet.',
    pending ? `Waiting for approval: **${pending.gamertag}** (${pending.platform})` : null,
    'Type your name exactly as it shows in game. A committee member approves it. Old names stay matched to your past games.'
  ].filter(Boolean).join('\n');
  return json({
    type: 9,
    data: {
      custom_id: 'gtagform',
      title: approved ? 'Change my gamertag' : 'Link my gamertag',
      components: [
        { type: 10, content: status },
        { type: 18, label: 'Gamertag or PSN name', component: { type: 4, custom_id: 'name', style: 1, min_length: 2, max_length: 32, required: true, ...(approved ? { value: approved.gamertag } : {}) } },
        {
          type: 18, label: 'Platform',
          component: { type: 3, custom_id: 'platform', min_values: 1, max_values: 1, options: PLATFORM_CHOICES.map((p) => ({ label: p.name, value: p.value, ...(approved?.platform === p.value ? { default: true } : {}) })) }
        }
      ]
    }
  });
}

// ---- stats, team, standings, leaders

async function menuStats(interaction, env, targetId) {
  await ensureSchema(requireDb(env));
  const text = await statsCommand(interaction, env, targetId ? { player: targetId } : {});
  return {
    content: text,
    components: [
      actionRow({ type: 5, custom_id: 'look:player', placeholder: 'Look up another player' }),
      actionRow(btn('League leaders', 'menu:leaders'), btn('Standings', 'menu:standings'))
    ]
  };
}

async function menuLeaders(env, category = 'pts') {
  const text = await leadersCommand(env, { category });
  return {
    content: text,
    components: [actionRow(stringSelect('ldr:cat', 'Pick a category', Object.entries(CATEGORY_NAMES).map(([value, label]) => ({ label, value, ...(value === category ? { default: true } : {}) }))))]
  };
}

async function menuStandings(env) {
  await ensureSchema(requireDb(env));
  return { content: await standingsCommand(env, {}), components: [actionRow(btn('League leaders', 'menu:leaders'))] };
}

async function menuTeam(interaction, env, franchiseId) {
  const db = requireDb(env);
  await ensureSchema(db);
  const fid = franchiseId ?? await myFranchiseId(db, invokerId(interaction));
  const teams = (await db.prepare('SELECT franchise_id, name FROM franchises ORDER BY name').all()).results ?? [];
  const picker = teams.length ? [actionRow(stringSelect('team:pick', 'Look at another team', teams.map((t) => ({ label: t.name.slice(0, 100), value: t.franchise_id, ...(t.franchise_id === fid ? { default: true } : {}) }))))] : [];
  if (!fid) return { content: 'You aren\'t on a team yet. Pick a team to look at.', components: picker };
  return {
    content: await capCommand(interaction, env, { franchise: fid }),
    components: [...picker, actionRow(btn('Playoff eligibility', `team:elig:${fid}`))]
  };
}

// ---- GM tools

async function gmFranchise(db, me) {
  const gm = await db.prepare('SELECT * FROM franchises WHERE gm_discord_id = ?').bind(me).first();
  if (gm) return gm;
  return db.prepare("SELECT * FROM franchises WHERE captain_discord_id = ? AND (gm_discord_id IS NULL OR gm_discord_id = '')").bind(me).first();
}

async function priceFor(db, playerId, season) {
  return db.prepare('SELECT * FROM player_prices WHERE player_id = ? AND season = ?').bind(playerId, season).first();
}

// Unsigned players with a published price for the season (the free-agent pool and the draft pool).
async function freeAgents(db, season) {
  return (await db.prepare(`
    SELECT p.player_id, p.display_name, p.discord_id, p.position, pr.tier, pr.fp_cost, pr.source
    FROM players p JOIN player_prices pr ON pr.player_id = p.player_id AND pr.season = ?
    WHERE NOT EXISTS (SELECT 1 FROM contracts c WHERE c.player_id = p.player_id AND c.status = 'Active'
      AND c.start_season + c.years - 1 + (CASE WHEN c.option_status = 'Exercised' THEN 1 ELSE 0 END) >= ?)
    ORDER BY pr.fp_cost DESC, p.display_name`).bind(season, season).all()).results ?? [];
}

const playerOption = (p, extra = {}) => ({
  label: `${p.display_name} · ${p.tier} · ${p.fp_cost} FP`.slice(0, 100),
  value: p.player_id,
  ...(p.position ? { description: `Position: ${p.position}`.slice(0, 100) } : {}),
  ...extra
});
const backToGm = () => actionRow(btn('Back to GM tools', 'menu:gm'));

async function rosterOf(db, franchiseId, season) {
  return (await franchiseContracts(db, franchiseId))
    .filter((c) => onRosterIn(c, season))
    .sort((a, b) => b.pcv - a.pcv || String(a.display_name).localeCompare(String(b.display_name)));
}

async function menuGm(interaction, env) {
  const db = requireDb(env);
  await ensureSchema(db);
  const fr = await gmFranchise(db, invokerId(interaction));
  if (!fr) return GM_ONLY;
  const { season, phase } = await leagueState(db);
  const result = evaluateRoster(await franchiseContracts(db, fr.franchise_id), season);
  return {
    content: [
      `**GM tools · ${fr.name}** · Season ${season} (${phase === 'in-season' ? 'season in progress' : 'offseason'})`,
      checkText(result, season),
      'Offers go to the player, who accepts or declines. Releases and trades go to the Commissioner for approval. DREW checks the cap rules before anything is sent.'
    ].join('\n'),
    components: [actionRow(btn('Offer a contract', 'gm:offer', 1), btn('Release a player', 'gm:release'), btn('Propose a trade', 'gm:trade'), btn('My team', 'menu:team'))]
  };
}

async function offerStart(db, me, tier) {
  const fr = await gmFranchise(db, me);
  if (!fr) return GM_ONLY;
  const { season } = await leagueState(db);
  let pool = await freeAgents(db, season);
  if (!pool.length) return { content: 'No free agents have a published price yet. The Commissioner publishes prices before free agency.', components: [backToGm()] };
  if (pool.length > 25 && !tier) {
    const counts = TIER_ORDER.map((t) => [t, pool.filter((p) => p.tier === t).length]).filter(([, n]) => n);
    return {
      content: `**Offer a contract** · ${pool.length} free agents. Pick a tier first.`,
      components: [actionRow(...counts.map(([t, n]) => btn(`${t} (${n})`, `gmo:tier:${t}`))), backToGm()]
    };
  }
  if (tier) pool = pool.filter((p) => p.tier === tier);
  return {
    content: `**Offer a contract**${tier ? ` · ${tier}` : ''} · Pick a player. The salary is the league's published price; you only choose how many seasons.${pool.length > 25 ? `\nShowing the first 25 of ${pool.length}.` : ''}`,
    components: [actionRow(stringSelect('gmo:pick', 'Choose a free agent', pool.map((p) => playerOption(p)))), backToGm()]
  };
}

const offerContract = (p, fid, season, years) => ({ player_id: p.player_id, franchise_id: fid, tier: p.tier, pcv: TIERS[p.tier].pcv, fp_cost: p.fp_cost, start_season: season, years, option_status: 'None', status: 'Active' });

async function offerPlans(db, fr, playerId) {
  const { season } = await leagueState(db);
  const p = (await freeAgents(db, season)).find((x) => x.player_id === playerId);
  if (!p) return { error: 'That player is no longer a free agent.' };
  const current = await franchiseContracts(db, fr.franchise_id);
  const before = evaluateRoster(current, season);
  const results = [1, 2, 3].map((y) => evaluateRoster([...current, offerContract(p, fr.franchise_id, season, y)], season, before.shortfall));
  return { p, season, results };
}

async function offerPreview(db, me, playerId) {
  const fr = await gmFranchise(db, me);
  if (!fr) return GM_ONLY;
  const plan = await offerPlans(db, fr, playerId);
  if (plan.error) return { content: plan.error, components: [actionRow(btn('Back', 'gm:offer'))] };
  const { p, season, results } = plan;
  const earlier = (await db.prepare("SELECT payload FROM pending_tx WHERE kind = 'offer' AND status = 'Offered'").all()).results
    ?.some((r) => { const o = JSON.parse(r.payload); return o.player_id === p.player_id && o.franchise_id === fr.franchise_id; });
  return {
    content: [
      `**Offer to ${p.display_name}** · ${p.tier} · ${p.fp_cost} FP per season`,
      `**${fr.name} after signing:**`,
      checkText(results[0], season),
      ...[2, 3].filter((y) => !results[y - 1].legal).map((y) => `❌ ${y} seasons doesn't fit: ${results[y - 1].problems.join('; ')}`),
      earlier ? 'This replaces your earlier offer to this player.' : null,
      'Pick how many seasons. The player sees your offer and decides; nothing changes until they accept.'
    ].filter(Boolean).join('\n'),
    components: [
      actionRow(...[1, 2, 3].map((y) => btn(`Offer ${y} season${y > 1 ? 's' : ''}`, `gmo:send:${p.player_id}:${y}`, 3, !results[y - 1].legal))),
      actionRow(btn('Back', 'gm:offer'))
    ]
  };
}

async function offerSend(env, db, me, playerId, years) {
  const fr = await gmFranchise(db, me);
  if (!fr) return GM_ONLY;
  const plan = await offerPlans(db, fr, playerId);
  if (plan.error) return { content: plan.error, components: [backToGm()] };
  const { p, season, results } = plan;
  if (![1, 2, 3].includes(years) || !results[years - 1].legal) return { content: 'That offer doesn\'t fit your cap rules anymore.', components: [backToGm()] };
  const payload = { player_id: p.player_id, franchise_id: fr.franchise_id, years, season, tier: p.tier, fp_cost: p.fp_cost };
  const statements = [];
  for (const r of (await db.prepare("SELECT id, payload FROM pending_tx WHERE kind = 'offer' AND status = 'Offered'").all()).results ?? []) {
    const o = JSON.parse(r.payload);
    if (o.player_id === p.player_id && o.franchise_id === fr.franchise_id) statements.push(db.prepare("UPDATE pending_tx SET status = 'Replaced' WHERE id = ?").bind(r.id));
  }
  if (statements.length) await db.batch(statements);
  const row = await db.prepare("INSERT INTO pending_tx (kind, payload, created_by, created_at, status) VALUES ('offer', ?, ?, ?, 'Offered') RETURNING id")
    .bind(JSON.stringify(payload), me, nowIso()).first();
  await audit(db, me, 'pending_tx', row.id, 'offer', null, JSON.stringify(payload), 'Contract offer sent').run();
  const terms = `${p.tier} · ${p.fp_cost} FP per season · ${years} season${years > 1 ? 's' : ''}`;
  const dm = p.discord_id ? await dmUser(env, p.discord_id, `**${fr.name}** offered you a contract: ${terms}.\nTo accept or decline, type \`/drew menu\` in the league server and tap **Offers & requests**.`) : false;
  return {
    content: `Offer sent to **${p.display_name}**: ${terms}.\nThey'll see it under **Offers & requests**${dm ? ' and got a direct message' : ''}. You can withdraw it there until they answer.`,
    components: [backToGm()]
  };
}

async function offerDecision(env, db, me, id, action) {
  const tx = await db.prepare('SELECT * FROM pending_tx WHERE id = ?').bind(id).first();
  if (!tx || tx.kind !== 'offer' || tx.status !== 'Offered') return 'This offer is no longer open.';
  const o = JSON.parse(tx.payload);
  const team = await franchiseOf(db, o.franchise_id);
  const player = await playerById(db, o.player_id);
  if (action === 'withdraw') {
    const fr = await gmFranchise(db, me);
    if (fr?.franchise_id !== o.franchise_id) return 'Only the team that sent this offer can withdraw it.';
    await db.batch([
      db.prepare("UPDATE pending_tx SET status = 'Withdrawn', decided_by = ?, decided_at = ? WHERE id = ? AND status = 'Offered'").bind(me, nowIso(), id),
      audit(db, me, 'pending_tx', id, 'status', 'Offered', 'Withdrawn', null)
    ]);
    return `Offer to ${player?.display_name ?? o.player_id} withdrawn.`;
  }
  if (player?.discord_id !== me) return 'This offer is for another player.';
  if (action === 'decline') {
    await db.batch([
      db.prepare("UPDATE pending_tx SET status = 'Declined', decided_by = ?, decided_at = ? WHERE id = ? AND status = 'Offered'").bind(me, nowIso(), id),
      audit(db, me, 'pending_tx', id, 'status', 'Offered', 'Declined', null)
    ]);
    await dmUser(env, tx.created_by, `${player.display_name} declined your contract offer.`);
    return `You declined ${team?.name ?? 'the team'}'s offer.`;
  }
  const { season } = await leagueState(db);
  const price = await priceFor(db, o.player_id, season);
  if (o.season !== season || !price || price.tier !== o.tier || price.fp_cost !== o.fp_cost) {
    return 'Your published price changed after this offer was sent, so it can\'t be accepted. Ask the team to send a new offer.';
  }
  const plan = await planSign(db, { player_id: o.player_id, franchise: o.franchise_id, tier: o.tier, fp_cost: o.fp_cost, years: o.years, source: price.source || 'Published price' });
  if (plan.error) return plan.error;
  if (!plan.result.legal) return `This signing would break ${plan.franchise.name}'s roster rules right now (${plan.result.problems.join('; ')}), so it can't go through. The team can make room and send it again.`;
  const claimed = await db.prepare("UPDATE pending_tx SET status = 'Accepted', decided_by = ?, decided_at = ? WHERE id = ? AND status = 'Offered' RETURNING id").bind(me, nowIso(), id).first();
  if (!claimed) return 'This offer is no longer open.';
  await recordSigning(env, db, plan, me, `Accepted offer #${id}`);
  for (const r of (await db.prepare("SELECT * FROM pending_tx WHERE kind = 'offer' AND status = 'Offered'").all()).results ?? []) {
    if (JSON.parse(r.payload).player_id !== o.player_id) continue;
    await db.prepare("UPDATE pending_tx SET status = 'Closed', decided_at = ? WHERE id = ?").bind(nowIso(), r.id).run();
    await dmUser(env, r.created_by, `${player.display_name} signed with another team, so your offer is closed.`);
  }
  await dmUser(env, tx.created_by, `${player.display_name} accepted your offer and is signed: ${o.tier} · ${o.fp_cost} FP per season · ${o.years} season${o.years > 1 ? 's' : ''}.`);
  return `You signed with **${plan.franchise.name}**: ${o.tier} · ${o.fp_cost} FP per season · ${o.years} season${o.years > 1 ? 's' : ''}. It's announced in #transactions.`;
}

async function requestApproval(env, db, requester, kind, payload, preview, existingId) {
  let id = existingId;
  if (id) {
    await db.prepare("UPDATE pending_tx SET status = 'Pending', payload = ? WHERE id = ?").bind(JSON.stringify(payload), id).run();
  } else {
    id = (await db.prepare("INSERT INTO pending_tx (kind, payload, created_by, created_at, status) VALUES (?, ?, ?, ?, 'Pending') RETURNING id")
      .bind(kind, JSON.stringify(payload), requester, nowIso()).first()).id;
  }
  await postToChannel(env, 'report-review', {
    content: `**Commissioner approval needed** (#${id})\n${preview}\nRequested by <@${requester}>`.slice(0, 1990),
    allowed_mentions: { parse: [] },
    components: [actionRow(btn('Approve', `tx:approve:${id}`, 3), btn('Turn down', `tx:cancel:${id}`, 4))]
  });
  return id;
}

async function releaseStart(db, me) {
  const fr = await gmFranchise(db, me);
  if (!fr) return GM_ONLY;
  const { season } = await leagueState(db);
  const roster = await rosterOf(db, fr.franchise_id, season);
  if (!roster.length) return { content: 'Your team has no signed players.', components: [backToGm()] };
  return {
    content: '**Release a player** · Pick the player. You\'ll see what it costs before anything is sent.',
    components: [actionRow(stringSelect('gmr:pick', 'Choose a player', roster.map((c) => ({ label: `${c.display_name ?? c.player_id} · ${c.tier} · ${c.fp_cost} FP`.slice(0, 100), value: c.player_id, description: `Signed through season ${contractEnd(c)}` })))), backToGm()]
  };
}

async function releaseOptions(db, fr, playerId) {
  const contract = await activeContract(db, playerId);
  if (!contract || contract.franchise_id !== fr.franchise_id) return { error: 'That player isn\'t signed with your team.' };
  const dead = await planRelease(db, { player_id: playerId, method: 'deadcap' });
  const buy = await planRelease(db, { player_id: playerId, method: 'buyout' });
  return { contract, dead, buy };
}

async function releasePreview(db, me, playerId) {
  const fr = await gmFranchise(db, me);
  if (!fr) return GM_ONLY;
  const r = await releaseOptions(db, fr, playerId);
  if (r.error) return { content: r.error, components: [backToGm()] };
  const { contract, dead, buy } = r;
  const name = dead.player.display_name;
  return {
    content: [
      `**Release ${name}?** ${contract.tier} · ${contract.fp_cost} FP per season, signed through season ${dead.lastGuaranteed}.`,
      `• **Release:** ${name} leaves now. ${contract.fp_cost} FP per season stays on your cap through season ${dead.lastGuaranteed}.`,
      buy.error ? `• **Buy out:** not available — ${buy.error}` : `• **Buy out:** ${name} leaves now. You pay ${buy.cost} FP once (${buy.fromCurrent} from this season's unused FP, ${buy.fromBank} from saved FP) and the rest comes off your cap.`,
      'Either one goes to the Commissioner for approval.'
    ].join('\n'),
    components: [actionRow(btn('Release (salary stays)', `gmr:dead:${playerId}`, 4), btn('Buy out', `gmr:buy:${playerId}`, 4, Boolean(buy.error)), btn('Back', 'gm:release'))]
  };
}

async function releaseSend(env, db, me, playerId, method) {
  const fr = await gmFranchise(db, me);
  if (!fr) return GM_ONLY;
  const r = await releaseOptions(db, fr, playerId);
  if (r.error) return { content: r.error, components: [backToGm()] };
  const plan = method === 'buyout' ? r.buy : r.dead;
  if (plan.error) return { content: plan.error, components: [backToGm()] };
  const open = (await db.prepare("SELECT payload FROM pending_tx WHERE kind = 'release' AND status = 'Pending'").all()).results ?? [];
  if (open.some((t) => JSON.parse(t.payload).player_id === playerId)) return { content: 'A release for this player is already waiting for the Commissioner.', components: [backToGm()] };
  const name = plan.player.display_name;
  const preview = method === 'buyout'
    ? `**Buyout** — ${fr.name} releases ${name}. Cost ${plan.cost} FP (${plan.fromCurrent} from this season's unused FP, ${plan.fromBank} from saved FP). ${name} becomes a free agent.`
    : `**Release** — ${fr.name} releases ${name}. ${r.contract.fp_cost} FP per season stays on their cap through season ${plan.lastGuaranteed}. ${name} becomes a free agent.`;
  await requestApproval(env, db, me, 'release', { player_id: playerId, method: method === 'buyout' ? 'buyout' : 'deadcap', reason: `Requested by ${fr.name}'s GM` }, preview);
  return { content: `Sent to the Commissioner: ${method === 'buyout' ? 'buy out' : 'release'} ${name}. You'll get a message when it's decided, and it shows under **Offers & requests** until then.`, components: [backToGm()] };
}

// ---- trades: GM builds it, the other GM accepts, each moving player agrees, the Commissioner approves.

async function tradeStart(db, me) {
  const fr = await gmFranchise(db, me);
  if (!fr) return GM_ONLY;
  const teams = ((await db.prepare('SELECT franchise_id, name FROM franchises ORDER BY name').all()).results ?? []).filter((t) => t.franchise_id !== fr.franchise_id);
  if (!teams.length) return { content: 'There are no other teams yet.', components: [backToGm()] };
  return {
    content: '**Propose a trade** · Pick the team you want to trade with.',
    components: [actionRow(stringSelect('gmt:team', 'Choose a team', teams.map((t) => ({ label: t.name.slice(0, 100), value: t.franchise_id })))), backToGm()]
  };
}

async function tradeCreate(db, me, otherId) {
  const fr = await gmFranchise(db, me);
  if (!fr) return GM_ONLY;
  if (!(await franchiseOf(db, otherId)) || otherId === fr.franchise_id) return { content: 'Pick another team.', components: [backToGm()] };
  await db.prepare("UPDATE pending_tx SET status = 'Abandoned' WHERE kind = 'trade' AND status = 'Draft' AND created_by = ?").bind(me).run();
  const row = await db.prepare("INSERT INTO pending_tx (kind, payload, created_by, created_at, status) VALUES ('trade', ?, ?, ?, 'Draft') RETURNING id")
    .bind(JSON.stringify({ franchise_a: fr.franchise_id, franchise_b: otherId, players_a: [], players_b: [] }), me, nowIso()).first();
  return renderTrade(db, await db.prepare('SELECT * FROM pending_tx WHERE id = ?').bind(row.id).first());
}

const tradeOpts = (o) => ({ franchise_a: o.franchise_a, players_a: o.players_a.join(','), franchise_b: o.franchise_b, players_b: o.players_b.join(',') });

async function playerNames(db, ids) {
  const out = [];
  for (const id of ids) out.push((await playerById(db, id))?.display_name ?? id);
  return out.join(', ') || 'nobody';
}

async function tradeSummary(db, o) {
  const plan = await planTrade(db, tradeOpts(o));
  if (plan.error) return { plan, text: plan.error, legal: false };
  const text = [
    `**${plan.a.name}** send: ${await playerNames(db, o.players_a)}`,
    `**${plan.b.name}** send: ${await playerNames(db, o.players_b)}`,
    'Contracts move as they are (tier, salary, seasons left). No FP changes hands.',
    `**${plan.a.name} after:**\n${checkText(plan.resultA, plan.season)}`,
    `**${plan.b.name} after:**\n${checkText(plan.resultB, plan.season)}`
  ].join('\n');
  return { plan, text, legal: plan.resultA.legal && plan.resultB.legal };
}

async function renderTrade(db, tx) {
  const o = JSON.parse(tx.payload);
  const { season } = await leagueState(db);
  const [a, b] = [await franchiseOf(db, o.franchise_a), await franchiseOf(db, o.franchise_b)];
  const rosterA = await rosterOf(db, o.franchise_a, season);
  const rosterB = await rosterOf(db, o.franchise_b, season);
  const opt = (c, chosen) => ({ label: `${c.display_name ?? c.player_id} · ${c.tier} · ${c.fp_cost} FP`.slice(0, 100), value: c.player_id, ...(chosen.includes(c.player_id) ? { default: true } : {}) });
  const any = o.players_a.length + o.players_b.length > 0;
  const summary = any ? await tradeSummary(db, o) : null;
  const components = [];
  if (rosterA.length) components.push(actionRow(stringSelect(`gmt:send:${tx.id}`, 'Players you send', rosterA.map((c) => opt(c, o.players_a)), { min: 0, max: rosterA.length })));
  if (rosterB.length) components.push(actionRow(stringSelect(`gmt:get:${tx.id}`, `Players you get from ${b.name}`.slice(0, 150), rosterB.map((c) => opt(c, o.players_b)), { min: 0, max: rosterB.length })));
  components.push(actionRow(btn(`Send to ${b.name}`, `gmt:submit:${tx.id}`, 3, !summary?.legal), btn('Cancel', `gmt:cancel:${tx.id}`)));
  return {
    content: [
      `**Trade: ${a.name} ↔ ${b.name}** · Pick who moves in the lists below.`,
      summary ? summary.text : 'Nobody picked yet.',
      summary && !summary.legal ? '❌ This trade doesn\'t fit the rules yet. Change the players.' : null,
      'Next: their GM accepts, each player in the trade agrees, then the Commissioner approves.'
    ].filter(Boolean).join('\n').slice(0, 1990),
    components
  };
}

async function tradeDraft(db, me, id) {
  const tx = await db.prepare('SELECT * FROM pending_tx WHERE id = ?').bind(id).first();
  if (!tx || tx.kind !== 'trade' || tx.status !== 'Draft' || tx.created_by !== me) return null;
  return tx;
}

async function tradeSelect(db, me, id, side, values) {
  const tx = await tradeDraft(db, me, id);
  if (!tx) return 'This trade draft is closed. Start again from **GM tools**.';
  const o = JSON.parse(tx.payload);
  o[side === 'send' ? 'players_a' : 'players_b'] = values ?? [];
  await db.prepare('UPDATE pending_tx SET payload = ? WHERE id = ?').bind(JSON.stringify(o), id).run();
  return renderTrade(db, { ...tx, payload: JSON.stringify(o) });
}

async function tradeSubmit(env, db, me, id) {
  const tx = await tradeDraft(db, me, id);
  if (!tx) return 'This trade draft is closed. Start again from **GM tools**.';
  const o = JSON.parse(tx.payload);
  const summary = await tradeSummary(db, o);
  if (!summary.legal) return renderTrade(db, tx);
  for (const pid of [...o.players_a, ...o.players_b]) {
    const p = await playerById(db, pid);
    if (p?.discord_id === me) return { content: 'You can\'t trade yourself. The Commissioner handles a GM\'s own trade directly.', components: [backToGm()] };
    if (!p?.discord_id) return { content: `${p?.display_name ?? pid} has no linked Discord account, so they can't agree to the trade. Ask the Commissioner to link them first.`, components: [backToGm()] };
  }
  await db.batch([
    db.prepare("UPDATE pending_tx SET status = 'Awaiting team' WHERE id = ? AND status = 'Draft'").bind(id),
    audit(db, me, 'pending_tx', id, 'status', 'Draft', 'Awaiting team', 'Trade proposed')
  ]);
  const b = summary.plan.b;
  const other = b.gm_discord_id || b.captain_discord_id;
  const dm = await dmUser(env, other, `**${summary.plan.a.name}** proposed a trade with your team.\nType \`/drew menu\` in the league server and tap **Offers & requests** to accept or decline.`);
  return {
    content: `Trade sent to **${b.name}**${dm ? ' (their GM got a direct message)' : ''}.\nNext: their GM accepts, each player in the trade agrees, then the Commissioner approves. You can withdraw it under **Offers & requests**.`,
    components: [backToGm()]
  };
}

async function sendTradeToCommissioner(env, db, tx, o) {
  const summary = await tradeSummary(db, o);
  const handled = Object.entries(o.consents ?? {}).filter(([, v]) => v === 'commissioner').map(([pid]) => pid);
  const preview = [
    '**Trade**',
    summary.text,
    handled.length ? `⚠️ Get consent privately from: ${await playerNames(db, handled)} (a GM in the trade).` : 'Both GMs accepted and every player in the trade agreed in DREW.'
  ].join('\n');
  await requestApproval(env, db, tx.created_by, 'trade', o, preview, tx.id);
}

async function tradeRespond(env, db, me, id, action) {
  const tx = await db.prepare('SELECT * FROM pending_tx WHERE id = ?').bind(id).first();
  if (!tx || tx.kind !== 'trade') return 'This trade is no longer open.';
  const o = JSON.parse(tx.payload);
  const [a, b] = [await franchiseOf(db, o.franchise_a), await franchiseOf(db, o.franchise_b)];
  const gmIds = [a?.gm_discord_id, b?.gm_discord_id].filter(Boolean);
  const notifyGms = async (text) => { for (const t of [a, b]) await dmUser(env, t?.gm_discord_id || t?.captain_discord_id, text); };

  if (action === 'withdraw') {
    if (tx.created_by !== me || !['Awaiting team', 'Awaiting players'].includes(tx.status)) return 'This trade can\'t be withdrawn now.';
    await db.batch([db.prepare("UPDATE pending_tx SET status = 'Withdrawn' WHERE id = ?").bind(id), audit(db, me, 'pending_tx', id, 'status', tx.status, 'Withdrawn', null)]);
    await dmUser(env, b?.gm_discord_id || b?.captain_discord_id, `${a?.name} withdrew their trade proposal.`);
    return 'Trade withdrawn.';
  }
  if (action === 'accept' || action === 'decline') {
    if (tx.status !== 'Awaiting team') return 'This trade is no longer waiting on your team.';
    if ((await gmFranchise(db, me))?.franchise_id !== o.franchise_b) return `Only ${b?.name}'s GM can answer this trade.`;
    if (action === 'decline') {
      await db.batch([db.prepare("UPDATE pending_tx SET status = 'Declined', decided_by = ?, decided_at = ? WHERE id = ?").bind(me, nowIso(), id), audit(db, me, 'pending_tx', id, 'status', tx.status, 'Declined', null)]);
      await dmUser(env, tx.created_by, `${b?.name} declined your trade proposal.`);
      return 'Trade declined.';
    }
    const summary = await tradeSummary(db, o);
    if (!summary.legal) return `This trade doesn't fit the rules anymore (rosters changed). Decline it and ask ${a?.name} for a new one.`;
    const consents = {};
    for (const pid of [...o.players_a, ...o.players_b]) {
      const p = await playerById(db, pid);
      consents[pid] = gmIds.includes(p?.discord_id) ? 'commissioner' : 'waiting';
    }
    const next = { ...o, consents };
    const waiting = Object.entries(consents).filter(([, v]) => v === 'waiting').map(([pid]) => pid);
    await db.batch([
      db.prepare("UPDATE pending_tx SET status = 'Awaiting players', payload = ? WHERE id = ? AND status = 'Awaiting team'").bind(JSON.stringify(next), id),
      audit(db, me, 'pending_tx', id, 'status', 'Awaiting team', 'Awaiting players', `Accepted by ${b?.name}`)
    ]);
    if (!waiting.length) {
      await sendTradeToCommissioner(env, db, tx, next);
      await notifyGms(`The ${a?.name}–${b?.name} trade is with the Commissioner for approval.`);
      return 'Trade accepted. It\'s now with the Commissioner for approval.';
    }
    for (const pid of waiting) {
      const p = await playerById(db, pid);
      await dmUser(env, p.discord_id, `You're part of a trade between **${a?.name}** and **${b?.name}**. Type \`/drew menu\` in the league server and tap **Offers & requests** to agree or say no.`);
    }
    return `Trade accepted. Next, ${waiting.length} player${waiting.length > 1 ? 's' : ''} in the trade need${waiting.length > 1 ? '' : 's'} to agree, then the Commissioner approves.`;
  }
  // a player agreeing or saying no
  if (tx.status !== 'Awaiting players') return 'This trade is no longer waiting on players.';
  const me_player = await playerByDiscord(db, me);
  if (!me_player || o.consents?.[me_player.player_id] !== 'waiting') return 'This trade isn\'t waiting on you.';
  if (action === 'no') {
    await db.batch([db.prepare("UPDATE pending_tx SET status = 'Declined', decided_by = ?, decided_at = ? WHERE id = ?").bind(me, nowIso(), id), audit(db, me, 'pending_tx', id, 'status', tx.status, 'Declined', 'A player in the trade said no')]);
    await notifyGms(`${me_player.display_name} said no to the ${a?.name}–${b?.name} trade, so it's off.`);
    return 'You said no. The trade is off and both GMs were told.';
  }
  const next = { ...o, consents: { ...o.consents, [me_player.player_id]: 'yes' } };
  const updated = await db.prepare("UPDATE pending_tx SET payload = ? WHERE id = ? AND status = 'Awaiting players' AND payload = ? RETURNING id").bind(JSON.stringify(next), id, tx.payload).first();
  if (!updated) return 'Someone else answered at the same moment. Open **Offers & requests** again.';
  await audit(db, me, 'pending_tx', id, 'consent', null, me_player.player_id, 'Player agreed to the trade').run();
  if (Object.values(next.consents).includes('waiting')) return 'Thanks, you agreed. Waiting on the other players in the trade.';
  await sendTradeToCommissioner(env, db, tx, next);
  await notifyGms(`Every player agreed to the ${a?.name}–${b?.name} trade. It's with the Commissioner for approval.`);
  return 'Thanks, you agreed. Everyone has, so it\'s now with the Commissioner.';
}

// ---- offers & requests: everything waiting on (or sent by) the person tapping

async function requestsView(db, me, notice) {
  await ensureSchema(db);
  const player = await playerByDiscord(db, me);
  const fr = await gmFranchise(db, me);
  const open = ((await db.prepare("SELECT * FROM pending_tx WHERE status IN ('Offered', 'Awaiting team', 'Awaiting players', 'Pending') ORDER BY id").all()).results ?? [])
    .map((t) => ({ ...t, o: JSON.parse(t.payload) }));
  const teamNames = Object.fromEntries(((await db.prepare('SELECT franchise_id, name FROM franchises').all()).results ?? []).map((f) => [f.franchise_id, f.name]));
  const tn = (id) => teamNames[id] ?? id;
  const pn = async (id) => (await playerById(db, id))?.display_name ?? id;
  const items = [];
  for (const t of open) {
    const o = t.o;
    if (t.kind === 'offer' && player && o.player_id === player.player_id) {
      items.push({ order: 0, text: `Contract offer from **${tn(o.franchise_id)}**: ${o.tier} · ${o.fp_cost} FP per season · ${o.years} season${o.years > 1 ? 's' : ''}`, row: actionRow(btn(`Accept ${tn(o.franchise_id)}`, `ofr:accept:${t.id}`, 3), btn('Decline', `ofr:decline:${t.id}`, 4)) });
    }
    if (t.kind === 'trade' && t.status === 'Awaiting players' && player && o.consents?.[player.player_id] === 'waiting') {
      const from = o.players_a.includes(player.player_id) ? o.franchise_a : o.franchise_b;
      const to = from === o.franchise_a ? o.franchise_b : o.franchise_a;
      items.push({ order: 0, text: `Trade: you'd move from **${tn(from)}** to **${tn(to)}**. Your contract stays the same. Do you agree?`, row: actionRow(btn('I agree', `trd:yes:${t.id}`, 3), btn('Say no', `trd:no:${t.id}`, 4)) });
    }
    if (fr && t.kind === 'trade' && t.status === 'Awaiting team' && o.franchise_b === fr.franchise_id) {
      items.push({ order: 1, text: `Trade offer from **${tn(o.franchise_a)}**: you get ${await playerNames(db, o.players_a)}; you send ${await playerNames(db, o.players_b)}.`, row: actionRow(btn('Accept trade', `trd:accept:${t.id}`, 3), btn('Decline trade', `trd:decline:${t.id}`, 4)) });
    }
    if (fr && t.kind === 'offer' && o.franchise_id === fr.franchise_id) {
      const name = await pn(o.player_id);
      items.push({ order: 2, text: `Your offer to ${name} (${o.years} season${o.years > 1 ? 's' : ''}) — waiting for them to answer`, row: actionRow(btn(`Withdraw offer to ${name}`, `ofr:withdraw:${t.id}`)) });
    }
    if (fr && t.kind === 'trade' && o.franchise_a === fr.franchise_id && ['Awaiting team', 'Awaiting players'].includes(t.status)) {
      items.push({ order: 2, text: `Your trade with ${tn(o.franchise_b)} — ${t.status === 'Awaiting team' ? 'waiting for their GM' : 'waiting for the players to agree'}`, row: actionRow(btn(`Withdraw trade with ${tn(o.franchise_b)}`, `trd:withdraw:${t.id}`)) });
    }
    if (t.status === 'Pending' && t.created_by === me) items.push({ order: 3, text: `With the Commissioner: ${t.kind} request #${t.id}` });
  }
  items.sort((x, y) => x.order - y.order);
  const rows = items.filter((i) => i.row).slice(0, 5);
  const more = items.filter((i) => i.row).length - rows.length;
  return {
    content: [
      notice ? `${notice}\n` : null,
      '**Offers & requests**',
      items.length ? items.map((i) => `• ${i.text}`).join('\n') : 'Nothing waiting for you right now.',
      more > 0 ? `Answer the first ones to see buttons for ${more} more.` : null
    ].filter(Boolean).join('\n').slice(0, 1990),
    components: rows.map((i) => i.row)
  };
}

// ---------------------------------------------------------------- draft
// State lives in settings.draft as JSON. Every pick checks that the state hasn't moved
// (two people can't take the same pick), creates a rookie contract at the published
// price, and then skips any team that is full or has no player that fits its rules.

const SCORECARD_PRICE = {
  15: ['Franchise', 16], 14: ['Franchise', 14], 13: ['Franchise', 12],
  12: ['Star', 11], 11: ['Star', 9], 10: ['Star', 7],
  9: ['Core', 6], 8: ['Core', 5], 7: ['Core', 4],
  6: ['Rotation', 4], 5: ['Rotation', 2],
  4: ['Development', 2], 3: ['Development', 1]
};
const LOTTERY_RANGES = [[1, 28], [29, 48], [49, 63], [64, 75], [76, 84], [85, 91], [92, 96], [97, 100]];

function priceFrom({ scorecard, tier, fp_cost: fpCost }) {
  if (scorecard != null && scorecard !== '') {
    const hit = SCORECARD_PRICE[Number(scorecard)];
    if (!hit) return { error: 'The scorecard total must be a whole number from 3 to 15.' };
    return { tier: hit[0], fp_cost: hit[1], source: 'Scorecard table' };
  }
  if (!TIERS[tier]) return { error: 'Give a scorecard total, or a tier and FP cost.' };
  const fp = Number(fpCost);
  const [lo, hi] = TIERS[tier].band;
  if (!Number.isInteger(fp) || fp < lo || fp > hi) return { error: `${tier} FP cost must be ${lo}–${hi}.` };
  return { tier, fp_cost: fp, source: 'Set by the Commissioner' };
}

function randomInt(lo, hi) {
  const span = hi - lo + 1;
  const limit = Math.floor(0x100000000 / span) * span;
  const buf = new Uint32Array(1);
  do crypto.getRandomValues(buf); while (buf[0] >= limit);
  return lo + (buf[0] % span);
}

async function getDraft(db) {
  const raw = await getSetting(db, 'draft', null);
  return { raw, state: raw ? JSON.parse(raw) : null };
}
const draftTotal = (st) => st.order.length * st.rounds;
function draftOwner(st, n) {
  const teams = st.order.length;
  const round = Math.floor(n / teams);
  const i = n % teams;
  return st.snake && round % 2 === 1 ? st.order[teams - 1 - i] : st.order[i];
}
const pickLabel = (st, n) => `${Math.floor(n / st.order.length) + 1}.${String((n % st.order.length) + 1).padStart(2, '0')}`;
const ROOKIE_YEARS = 2;
const draftContract = (st, fid, p) => ({ player_id: p.player_id, franchise_id: fid, tier: p.tier, pcv: TIERS[p.tier].pcv, fp_cost: p.fp_cost, start_season: st.season, years: ROOKIE_YEARS, option_status: 'None', status: 'Active' });

async function draftCandidates(db, st, fid) {
  const pool = await freeAgents(db, st.season);
  const current = await franchiseContracts(db, fid);
  const before = evaluateRoster(current, st.season);
  const legal = [];
  for (const p of pool) {
    if (!TIERS[p.tier]) continue;
    if (evaluateRoster([...current, draftContract(st, fid, p)], st.season, before.shortfall).legal) legal.push(p);
  }
  return { pool, legal, blocked: pool.length - legal.length, full: before.size >= ROSTER_MAX, before };
}

// Skip teams that can't pick (full roster or nobody fits), and mark the draft done at the end.
async function draftAdvance(db, st) {
  while (st.picks.length < draftTotal(st)) {
    const fid = draftOwner(st, st.picks.length);
    const { legal, full } = await draftCandidates(db, st, fid);
    if (!full && legal.length) break;
    st.picks.push({ fid, player_id: null, auto: true, note: full ? 'roster full' : 'no available player fits their rules' });
  }
  if (st.picks.length >= draftTotal(st)) st.status = 'done';
  return st;
}

async function teamNameMap(db) {
  return Object.fromEntries(((await db.prepare('SELECT * FROM franchises').all()).results ?? []).map((f) => [f.franchise_id, f]));
}

async function draftBoard(db, st) {
  const teams = await teamNameMap(db);
  const name = (fid) => teams[fid]?.name ?? fid;
  const total = draftTotal(st);
  const n = st.picks.length;
  const lines = [
    `**Season ${st.season} ${st.kind === 'inaugural' ? 'draft' : 'entry draft'}** · ${st.kind === 'inaugural' ? `${st.rounds} rounds, order reverses every round` : 'one round'}`,
    `Order: ${st.order.map((fid, i) => `${i + 1}. ${name(fid)}`).join(' · ')}`
  ];
  if (st.status === 'live') {
    const fid = draftOwner(st, n);
    const gm = teams[fid]?.gm_discord_id || teams[fid]?.captain_discord_id;
    lines.push(`**On the clock: ${name(fid)}**${gm ? ` (<@${gm}>)` : ''} · pick ${pickLabel(st, n)}, ${n + 1} of ${total}`);
  } else {
    lines.push(`**Draft ${n >= total ? 'complete' : 'ended'}.** ${st.picks.filter((p) => p.player_id).length} players drafted.`);
  }
  const recent = st.picks.map((p, i) => ({ ...p, i })).slice(-8).reverse();
  if (recent.length) {
    lines.push('Latest picks:');
    for (const p of recent) lines.push(`${pickLabel(st, p.i)} ${name(p.fid)} — ${p.player_id ? `**${p.name}** (${p.tier} · ${p.fp} FP)` : `skipped (${p.note})`}`);
  }
  if (st.status === 'live') lines.push(`GMs: tap **Make my pick** when you're on the clock. Drafted players get a ${ROOKIE_YEARS}-season rookie contract at their published price.`);
  return {
    content: lines.join('\n').slice(0, 1990),
    components: st.status === 'live' ? [actionRow(btn('Make my pick', 'dft:pick', 1), ...(st.kind === 'entry' ? [btn('Pass this pick', 'dft:pass')] : []))] : []
  };
}

async function draftChannelPost(env, message) {
  for (const name of ['draft', 'transactions']) {
    const channel = await findChannel(env, name);
    if (channel) {
      const posted = await discordApi('POST', `/channels/${channel.id}/messages`, env.DISCORD_BOT_TOKEN, message);
      return { channelId: channel.id, messageId: posted.id };
    }
  }
  throw new Error('#draft or #transactions was not found');
}

// Save the new state, refresh the board, and tag whoever is on the clock now.
async function draftPublish(env, db, st, headline) {
  const board = await draftBoard(db, st);
  await editChannelMessage(env, st.board_channel_id, st.board_message_id, board);
  const teams = await teamNameMap(db);
  let text = headline ?? '';
  let mention = [];
  if (st.status === 'live') {
    const fid = draftOwner(st, st.picks.length);
    const gm = teams[fid]?.gm_discord_id || teams[fid]?.captain_discord_id;
    text += `\nUp next: **${teams[fid]?.name ?? fid}**${gm ? ` <@${gm}>` : ''} (pick ${pickLabel(st, st.picks.length)})`;
    mention = gm ? [gm] : [];
  } else {
    text += '\n**The draft is over.** Contracts are on each team\'s page.';
  }
  try {
    await discordApi('POST', `/channels/${st.board_channel_id}/messages`, env.DISCORD_BOT_TOKEN, { content: text.trim().slice(0, 1990), allowed_mentions: { users: mention } });
  } catch (error) {
    console.error(`Draft post failed: ${error.message}`);
  }
}

async function saveDraft(db, oldRaw, st) {
  const row = await db.prepare("UPDATE settings SET value = ? WHERE key = 'draft' AND value = ? RETURNING key").bind(JSON.stringify(st), oldRaw).first();
  return Boolean(row);
}

async function adminDraft(interaction, env, opts) {
  const db = requireDb(env);
  const me = invokerId(interaction);
  const { raw, state } = await getDraft(db);
  const action = opts.action;
  if (action === 'start-inaugural' || action === 'start-entry') {
    const { season, phase } = await leagueState(db);
    if (phase !== 'offseason') return 'The draft runs in the offseason. Close the season first.';
    if (state?.status === 'live') return 'A draft is already running. End it first if you want to restart.';
    const teams = (await db.prepare('SELECT * FROM franchises ORDER BY name').all()).results ?? [];
    if (teams.length < 2) return 'Add the teams first.';
    if (!(await freeAgents(db, season)).length) return `No unsigned players have a published price for season ${season}. Publish prices first (\`/drew admin price\` or import prices).`;
    let order;
    let record;
    if (action === 'start-inaugural') {
      order = teams.map((t) => t.franchise_id);
      for (let i = order.length - 1; i > 0; i -= 1) {
        const j = randomInt(0, i);
        [order[i], order[j]] = [order[j], order[i]];
      }
      record = `**Season ${season} draft order** (drawn at random by DREW, <t:${unix(nowIso())}:f>):\n${order.map((fid, i) => `${i + 1}. ${teams.find((t) => t.franchise_id === fid).name}`).join('\n')}\n10 rounds; the order reverses every round.`;
    } else {
      if (teams.length !== LOTTERY_RANGES.length) return `The lottery odds are written for ${LOTTERY_RANGES.length} teams; the league has ${teams.length}. Update the rules before running it.`;
      const { fixtures } = await loadSeason(db, season - 1);
      if (season < 2 || !fixtures.length) return 'There is no finished previous season to base the lottery on. Use the first-season draft instead.';
      const worstToBest = computeStandings(fixtures, teams).map((r) => r.franchise_id).reverse();
      const draw = randomInt(1, 100);
      const winner = LOTTERY_RANGES.findIndex(([lo, hi]) => draw >= lo && draw <= hi);
      order = [worstToBest[winner], ...worstToBest.filter((_, i) => i !== winner)];
      const name = (fid) => teams.find((t) => t.franchise_id === fid).name;
      record = [
        `**Season ${season} draft lottery** (<t:${unix(nowIso())}:f>)`,
        ...worstToBest.map((fid, i) => `${name(fid)} (finished ${teams.length - i}${['st', 'nd', 'rd'][teams.length - i - 1] ?? 'th'}): tickets ${LOTTERY_RANGES[i][0]}–${LOTTERY_RANGES[i][1]}`),
        `Number drawn: **${draw}** → **${name(order[0])}** pick first.`,
        `Order: ${order.map((fid, i) => `${i + 1}. ${name(fid)}`).join(' · ')}`
      ].join('\n');
    }
    const st = await draftAdvance(db, { season, kind: action === 'start-inaugural' ? 'inaugural' : 'entry', rounds: action === 'start-inaugural' ? 10 : 1, snake: action === 'start-inaugural', order, picks: [], status: 'live', started_at: nowIso() });
    try { await postToChannel(env, 'announcements', { content: record.slice(0, 1990), allowed_mentions: { parse: [] } }); } catch (error) { console.error(`Draft announcement failed: ${error.message}`); }
    const posted = await draftChannelPost(env, { ...(await draftBoard(db, st)), allowed_mentions: { parse: [] } });
    st.board_channel_id = posted.channelId;
    st.board_message_id = posted.messageId;
    await db.batch([setSetting(db, 'draft', JSON.stringify(st)), audit(db, me, 'settings', 'draft', null, `${st.kind} season ${season}`, record.slice(0, 900))]);
    await draftPublish(env, db, st, '**The draft has started.**');
    return `Draft started and the order is posted in #announcements. The board is live${st.status === 'done' ? ', but no team could make a pick (check prices and rosters)' : ''}.`;
  }
  if (!state || state.status !== 'live') return 'No draft is running.';
  const st = structuredClone(state);
  if (action === 'end') {
    st.status = 'ended';
    if (!(await saveDraft(db, raw, st))) return 'The draft changed at the same moment. Try again.';
    await audit(db, me, 'settings', 'draft', 'live', 'ended', 'Ended by the Commissioner').run();
    await draftPublish(env, db, st, '**The Commissioner ended the draft.**');
    return 'Draft ended.';
  }
  if (action === 'pass') {
    const fid = draftOwner(st, st.picks.length);
    st.picks.push({ fid, player_id: null, note: 'skipped by the Commissioner' });
    await draftAdvance(db, st);
    if (!(await saveDraft(db, raw, st))) return 'The draft changed at the same moment. Try again.';
    await audit(db, me, 'settings', 'draft', null, `pick ${st.picks.length} skipped`, null).run();
    const teams = await teamNameMap(db);
    await draftPublish(env, db, st, `${teams[fid]?.name ?? fid}'s pick was skipped by the Commissioner.`);
    return 'Pick skipped.';
  }
  if (action === 'undo') {
    let undone = null;
    while (st.picks.length && !undone) {
      const p = st.picks.pop();
      if (p.player_id) undone = p;
    }
    if (!undone) return 'There is no pick to undo.';
    st.status = 'live';
    const contract = await db.prepare("SELECT * FROM contracts WHERE player_id = ? AND franchise_id = ? AND status = 'Active' AND fp_source = 'Draft' AND start_season = ? ORDER BY contract_id DESC LIMIT 1").bind(undone.player_id, undone.fid, st.season).first();
    const statements = [db.prepare("UPDATE settings SET value = ? WHERE key = 'draft' AND value = ?").bind(JSON.stringify(st), raw)];
    if (contract) {
      statements.unshift(
        db.prepare("DELETE FROM contracts WHERE contract_id = ? AND EXISTS (SELECT 1 FROM settings WHERE key = 'draft' AND value = ?)").bind(contract.contract_id, raw),
        db.prepare("UPDATE players SET franchise_id = NULL, updated_at = ? WHERE player_id = ? AND EXISTS (SELECT 1 FROM settings WHERE key = 'draft' AND value = ?)").bind(nowIso(), undone.player_id, raw)
      );
    }
    await db.batch(statements);
    if ((await getDraft(db)).raw !== JSON.stringify(st)) return 'The draft changed at the same moment. Try again.';
    await audit(db, me, 'contracts', contract?.contract_id ?? '-', 'draft pick', undone.player_id, null, 'Pick undone by the Commissioner').run();
    await draftPublish(env, db, st, `The Commissioner undid ${undone.name}'s pick.`);
    return `Undone: ${undone.name}. The same team is on the clock again.`;
  }
  return 'Choose a draft action.';
}

// Who can make the current pick: the team's GM (or captain if no GM), or the Commissioner.
async function canPick(interaction, env, team) {
  const me = invokerId(interaction);
  if ((team?.gm_discord_id || team?.captain_discord_id) === me) return true;
  return isCommissioner(await memberRoleNames(interaction, env));
}

async function draftPickView(interaction, env, n, tier, page = 0) {
  const db = requireDb(env);
  const { state: st } = await getDraft(db);
  if (!st || st.status !== 'live') return 'No draft is running right now.';
  if (n != null && n !== st.picks.length) return 'The board moved on: that pick was already made. Tap **Make my pick** on the board again.';
  const current = st.picks.length;
  const fid = draftOwner(st, current);
  const teams = await teamNameMap(db);
  if (!(await canPick(interaction, env, teams[fid]))) {
    const mine = await gmFranchise(db, invokerId(interaction));
    let next = null;
    if (mine) for (let k = current; k < draftTotal(st); k += 1) if (draftOwner(st, k) === mine.franchise_id) { next = k; break; }
    return `It isn't your pick. **${teams[fid]?.name ?? fid}** is on the clock.${next != null ? ` Your next pick is ${pickLabel(st, next)} (${next - current} pick${next - current === 1 ? '' : 's'} away).` : ''}`;
  }
  const { legal, blocked, before } = await draftCandidates(db, st, fid);
  const header = `**Pick ${pickLabel(st, current)} · ${teams[fid]?.name ?? fid}**`;
  if (!tier) {
    const counts = TIER_ORDER.map((t) => [t, legal.filter((p) => p.tier === t).length]).filter(([, c]) => c);
    return {
      content: [
        header,
        `${legal.length} player${legal.length === 1 ? '' : 's'} fit your rules${blocked ? ` (${blocked} more don't fit right now)` : ''}. Pick a tier.`,
        `Your team now:\n${checkText(before, st.season)}`,
        before.size >= ROSTER_MIN - 1 ? `Reminder: from ${ROSTER_MIN} players your team value must be at least ${PCV_FLOOR_PER_PLAYER} PCV per player.` : null
      ].filter(Boolean).join('\n'),
      components: counts.length ? [actionRow(...counts.map(([t, c]) => btn(`${t} (${c})`, `dft:tier:${current}:${t}:0`)))] : []
    };
  }
  const list = legal.filter((p) => p.tier === tier);
  const pages = Math.max(1, Math.ceil(list.length / 25));
  const pg = Math.min(Math.max(0, page), pages - 1);
  const shown = list.slice(pg * 25, pg * 25 + 25);
  if (!shown.length) return draftPickView(interaction, env, current);
  const nav = [btn('Back to tiers', `dft:tiers:${current}`)];
  if (pg > 0) nav.push(btn('Previous', `dft:tier:${current}:${tier}:${pg - 1}`));
  if (pg < pages - 1) nav.push(btn('More players', `dft:tier:${current}:${tier}:${pg + 1}`));
  return {
    content: `${header} · ${tier}${pages > 1 ? ` (page ${pg + 1} of ${pages})` : ''}\nPick a player. You'll confirm on the next step.`,
    components: [actionRow(stringSelect(`dft:sel:${current}`, 'Choose a player', shown.map((p) => playerOption(p)))), actionRow(...nav)]
  };
}

async function draftConfirmView(interaction, env, n, playerId) {
  const db = requireDb(env);
  const { state: st } = await getDraft(db);
  if (!st || st.status !== 'live' || st.picks.length !== n) return 'The board moved on: that pick was already made.';
  const p = (await freeAgents(db, st.season)).find((x) => x.player_id === playerId);
  if (!p) return draftPickView(interaction, env, n);
  return {
    content: `**Draft ${p.display_name}?** ${p.tier} · ${p.fp_cost} FP per season · ${ROOKIE_YEARS}-season rookie contract${p.position ? ` · ${p.position}` : ''}`,
    components: [actionRow(btn(`Draft ${p.display_name}`, `dft:ok:${n}:${p.player_id}`, 3), btn('Back', `dft:tiers:${n}`))]
  };
}

async function draftMakePick(interaction, env, n, playerId) {
  const db = requireDb(env);
  const me = invokerId(interaction);
  const { raw, state: st } = await getDraft(db);
  if (!st || st.status !== 'live' || st.picks.length !== n) return 'The board moved on: that pick was already made.';
  const fid = draftOwner(st, n);
  const teams = await teamNameMap(db);
  if (!(await canPick(interaction, env, teams[fid]))) return 'It isn\'t your pick anymore.';
  const p = (await draftCandidates(db, st, fid)).legal.find((x) => x.player_id === playerId);
  if (!p) {
    const view = await draftPickView(interaction, env, n);
    return typeof view === 'string' ? view : { ...view, content: `That player was taken or no longer fits your rules. Pick again.\n${view.content}` };
  }
  const next = structuredClone(st);
  next.picks.push({ fid, player_id: p.player_id, name: p.display_name, tier: p.tier, fp: p.fp_cost, by: me });
  const c = draftContract(st, fid, p);
  const guard = "EXISTS (SELECT 1 FROM settings WHERE key = 'draft' AND value = ?)";
  const now = nowIso();
  await db.batch([
    db.prepare(`INSERT INTO contracts (player_id, franchise_id, tier, pcv, fp_cost, fp_source, start_season, years, option_status, status, signed_at, signed_by) SELECT ?, ?, ?, ?, ?, 'Draft', ?, ?, 'None', 'Active', ?, ? WHERE ${guard}`)
      .bind(c.player_id, fid, c.tier, c.pcv, c.fp_cost, c.start_season, c.years, now, me, raw),
    db.prepare(`UPDATE players SET franchise_id = ?, updated_at = ? WHERE player_id = ? AND ${guard}`).bind(fid, now, p.player_id, raw),
    db.prepare("UPDATE settings SET value = ? WHERE key = 'draft' AND value = ?").bind(JSON.stringify(next), raw)
  ]);
  const savedRaw = JSON.stringify(next);
  if ((await getDraft(db)).raw !== savedRaw) return 'The board moved on: that pick was already made.';
  await audit(db, me, 'contracts', p.player_id, 'draft pick', null, `${pickLabel(st, n)} ${fid}`, `Drafted at ${p.fp_cost} FP per season for ${ROOKIE_YEARS} seasons`).run();
  const advanced = await draftAdvance(db, structuredClone(next));
  if (advanced.picks.length !== next.picks.length || advanced.status !== next.status) await saveDraft(db, savedRaw, advanced);
  await draftPublish(env, db, advanced, `Pick ${pickLabel(st, n)}: **${teams[fid]?.name ?? fid}** select **${p.display_name}** (${p.tier} · ${p.fp_cost} FP)`);
  return `You drafted **${p.display_name}** (${p.tier} · ${p.fp_cost} FP per season, ${ROOKIE_YEARS}-season rookie contract).`;
}

async function draftPass(interaction, env) {
  const db = requireDb(env);
  const { raw, state: st } = await getDraft(db);
  if (!st || st.status !== 'live') return 'No draft is running.';
  if (st.kind !== 'entry') return 'Teams can\'t pass in the first-season draft.';
  const fid = draftOwner(st, st.picks.length);
  const teams = await teamNameMap(db);
  if (!(await canPick(interaction, env, teams[fid]))) return 'Only the team on the clock can pass.';
  const next = structuredClone(st);
  next.picks.push({ fid, player_id: null, note: 'passed' });
  await draftAdvance(db, next);
  if (!(await saveDraft(db, raw, next))) return 'The board moved on. Try again.';
  await audit(db, invokerId(interaction), 'settings', 'draft', null, `${fid} passed`, null).run();
  await draftPublish(env, db, next, `**${teams[fid]?.name ?? fid}** passed.`);
  return 'You passed this pick.';
}

async function menuDraft(interaction, env) {
  const db = requireDb(env);
  const { state: st } = await getDraft(db);
  if (!st) return 'No draft has been held yet. The Commissioner starts it in the offseason.';
  return draftBoard(db, st);
}

// ---------------------------------------------------------------- Commissioner: menu post, prices, game lookup

async function adminPostMenu(interaction, env) {
  const channelId = interaction.channel_id ?? interaction.channel?.id;
  if (!channelId) return 'Run this inside the channel where the menu should go.';
  await discordApi('POST', `/channels/${channelId}/messages`, env.DISCORD_BOT_TOKEN, { ...menuMessage(), allowed_mentions: { parse: [] } });
  return 'Menu posted here. Pin it so everyone can find it. The buttons keep working after DREW updates.';
}

async function adminPrice(interaction, env, opts) {
  const db = requireDb(env);
  const me = invokerId(interaction);
  const player = await playerByDiscord(db, opts.player);
  if (!player) return 'That member isn\'t in the player list yet. Add them with `/drew admin player` first.';
  const season = opts.season ?? (await leagueState(db)).season;
  const price = priceFrom(opts);
  if (price.error) return price.error;
  const before = await priceFor(db, player.player_id, season);
  await db.batch([
    db.prepare('INSERT INTO player_prices (player_id, season, tier, fp_cost, source, set_by, set_at) VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT(player_id, season) DO UPDATE SET tier = excluded.tier, fp_cost = excluded.fp_cost, source = excluded.source, set_by = excluded.set_by, set_at = excluded.set_at')
      .bind(player.player_id, season, price.tier, price.fp_cost, price.source, me, nowIso()),
    audit(db, me, 'player_prices', `${player.player_id}:${season}`, 'price', before ? `${before.tier} ${before.fp_cost}` : null, `${price.tier} ${price.fp_cost}`, price.source)
  ]);
  const signed = await activeContract(db, player.player_id);
  return `Published: **${player.display_name}** · ${price.tier} · ${price.fp_cost} FP per season (season ${season}, ${price.source.toLowerCase()}).${signed ? ' They are under contract now, so this applies to their next contract.' : ''}`;
}

async function gameAutocomplete(interaction, env) {
  try {
    const db = requireDb(env);
    const top = interaction.data?.options?.[0];
    const leaf = top?.type === 2 ? top.options?.[0] : top;
    const focused = (leaf?.options ?? []).find((o) => o.focused);
    const text = String(focused?.value ?? '').toLowerCase();
    let rows = [];
    if (leaf?.name === 'report') rows = (await reportableGames(db, invokerId(interaction))).games;
    else if (leaf?.name === 'forfeit') rows = await gamesWithNames(db, "f.status NOT IN ('Final', 'Reported')", []);
    else if (leaf?.name === 'credit') rows = await gamesWithNames(db, "f.result_type = 'Forfeit'", []);
    const choices = rows
      .filter((fx) => !text || `${fx.home_name} ${fx.away_name} ${fx.fixture_id} week ${fx.week}`.toLowerCase().includes(text))
      .slice(0, 25)
      .map((fx) => ({ name: `Week ${fx.week}: ${fx.home_name} vs ${fx.away_name} (${fx.fixture_id})`.slice(0, 100), value: fx.fixture_id }));
    return json({ type: 8, data: { choices } });
  } catch (error) {
    console.error(`Autocomplete failed: ${error.message}`);
    return json({ type: 8, data: { choices: [] } });
  }
}

// ---------------------------------------------------------------- website data API (read-only)
// The website calls these. They reuse the same calculations as the bot, and never return
// Discord IDs, gamertags, screenshots, or review notes.

const apiJson = (body, status = 200) => new Response(JSON.stringify(body), {
  status,
  headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'public, max-age=60' }
});

function resultLine(fx, names) {
  const effect = gameEffect(fx);
  return {
    fixture_id: fx.fixture_id, season: fx.season, week: fx.week,
    home_id: fx.home_id, home: names[fx.home_id] ?? fx.home_id,
    away_id: fx.away_id, away: names[fx.away_id] ?? fx.away_id,
    status: fx.status, result_type: fx.result_type, winner_id: fx.winner_id ?? null,
    home_score: fx.home_score ?? null, away_score: fx.away_score ?? null,
    start: fx.agreed_start_utc ?? null, counted: Boolean(effect)
  };
}

async function apiContext(db, url) {
  await ensureSchema(db);
  const state = await leagueState(db);
  const asked = Number(url.searchParams.get('season'));
  const season = Number.isInteger(asked) && asked > 0 ? asked : state.season;
  const franchises = (await db.prepare('SELECT franchise_id, name FROM franchises ORDER BY name').all()).results ?? [];
  const names = Object.fromEntries(franchises.map((f) => [f.franchise_id, f.name]));
  return { ...state, season, currentSeason: state.season, franchises, names };
}

const publicStats = (r, names) => ({
  player_id: r.player_id, name: r.display_name ?? r.player_id, franchise_id: r.franchise_id ?? null,
  team: names[r.franchise_id] ?? null, gp: r.gp, pts: r.pts, reb: r.reb, ast: r.ast, stl: r.stl, blk: r.blk, tov: r.tov,
  fgm: r.fgm, fga: r.fga, tpm: r.tpm, tpa: r.tpa, ftm: r.ftm, fta: r.fta, efg: r.efg
});

const publicContract = (c) => ({
  player_id: c.player_id, name: c.display_name ?? c.player_id, tier: c.tier, pcv: c.pcv, fp_cost: c.fp_cost,
  fp_source: c.fp_source, start_season: c.start_season, end_season: contractEnd(c), status: c.status,
  option: c.option_status === 'Pending' ? 'undecided' : c.option_status === 'Exercised' ? 'exercised' : c.option_status === 'Declined' ? 'declined' : null
});

async function handleApi(request, env, url) {
  if (request.method !== 'GET') return apiJson({ error: 'Read-only' }, 405);
  if (!env.DB) return apiJson({ error: 'The league database is not connected.' }, 503);
  const db = env.DB;
  const ctx = await apiContext(db, url);
  const { season, names } = ctx;
  const parts = url.pathname.replace(/^\/api\/?/, '').split('/').filter(Boolean);
  const route = parts[0] ?? '';

  if (route === 'meta') {
    const seasons = ((await db.prepare('SELECT DISTINCT season FROM fixtures ORDER BY season').all()).results ?? []).map((r) => r.season);
    if (!seasons.includes(ctx.currentSeason)) seasons.push(ctx.currentSeason);
    return apiJson({ league_name: env.LEAGUE_NAME || 'NBA 2K League', season: ctx.currentSeason, phase: ctx.phase, seasons: seasons.sort((a, b) => a - b), teams: ctx.franchises });
  }

  const { fixtures, franchises } = await loadSeason(db, season);
  const standings = () => computeStandings(fixtures, franchises).map((r) => ({
    rank: r.rank, franchise_id: r.franchise_id, name: r.name, gp: r.gp, w: r.w, l: r.l, pct: r.pct,
    on_court: r.onCourt, on_court_needed: ON_COURT_NEEDED, pf: r.pf, pa: r.pa, diff: r.diff, forfeits: r.forfeits,
    remaining: r.remaining, seed: r.seed, can_qualify: r.canQualify, tie: Boolean(r.unresolvedTie)
  }));

  if (route === 'home') {
    const recent = fixtures.filter((f) => gameEffect(f))
      .sort((a, b) => String(b.updated_at ?? '').localeCompare(String(a.updated_at ?? ''))).slice(0, 8).map((f) => resultLine(f, names));
    const upcoming = fixtures.filter((f) => f.status === 'Time set' && f.agreed_start_utc && Date.parse(f.agreed_start_utc) > Date.now() - 3 * HOUR)
      .sort((a, b) => a.agreed_start_utc.localeCompare(b.agreed_start_utc)).slice(0, 6).map((f) => resultLine(f, names));
    const stats = await playerSeasonStats(db, season);
    const leaders = Object.fromEntries(['pts', 'reb', 'ast'].map((c) => [c, leaderList(stats, c).slice(0, 3).map(({ r, value }) => ({ ...publicStats(r, names), value }))]));
    return apiJson({ season, phase: ctx.phase, standings: standings(), recent, upcoming, leaders, leader_min_gp: LEADER_MIN_GP });
  }
  if (route === 'standings') return apiJson({ season, standings: standings(), playoff_spots: PLAYOFF_SPOTS, on_court_needed: ON_COURT_NEEDED });
  if (route === 'schedule') {
    const list = fixtures.slice().sort((a, b) => a.week - b.week || String(a.agreed_start_utc ?? '9').localeCompare(String(b.agreed_start_utc ?? '9')) || a.fixture_id.localeCompare(b.fixture_id));
    return apiJson({ season, fixtures: list.map((f) => resultLine(f, names)) });
  }
  if (route === 'players') {
    const stats = await playerSeasonStats(db, season);
    return apiJson({ season, players: stats.map((r) => publicStats(r, names)), leader_min_gp: LEADER_MIN_GP, efg_min_gp: EFG_MIN_GP, efg_min_fga: EFG_MIN_FGA });
  }
  if (route === 'leaders') {
    const category = url.searchParams.get('category') ?? 'pts';
    if (!CATEGORY_NAMES[category]) return apiJson({ error: 'Unknown category' }, 400);
    const stats = await playerSeasonStats(db, season);
    return apiJson({ season, category, label: CATEGORY_NAMES[category], leaders: leaderList(stats, category).map(({ r, value }) => ({ ...publicStats(r, names), value })) });
  }
  if (route === 'teams') {
    const table = standings();
    return apiJson({ season, teams: franchises.map((f) => ({ franchise_id: f.franchise_id, name: f.name, record: table.find((t) => t.franchise_id === f.franchise_id) ?? null })) });
  }
  if (route === 'team' && parts[1]) {
    const franchise = franchises.find((f) => f.franchise_id === parts[1]);
    if (!franchise) return apiJson({ error: 'No such team' }, 404);
    const contracts = await franchiseContracts(db, franchise.franchise_id);
    const capSeason = ctx.currentSeason;
    const evaluation = evaluateRoster(contracts, capSeason);
    const bank = await bankInfo(db, franchise.franchise_id, capSeason);
    const stats = (await playerSeasonStats(db, season)).filter((r) => r.franchise_id === franchise.franchise_id);
    const games = fixtures.filter((f) => f.home_id === franchise.franchise_id || f.away_id === franchise.franchise_id)
      .sort((a, b) => a.week - b.week || a.fixture_id.localeCompare(b.fixture_id)).map((f) => resultLine(f, names));
    const played = fixtures.filter((f) => gameEffect(f) === 'played' && (f.home_id === franchise.franchise_id || f.away_id === franchise.franchise_id));
    const forPts = played.reduce((n, f) => n + (f.home_id === franchise.franchise_id ? f.home_score : f.away_score), 0);
    const agPts = played.reduce((n, f) => n + (f.home_id === franchise.franchise_id ? f.away_score : f.home_score), 0);
    return apiJson({
      season, cap_season: capSeason, phase: ctx.phase, team: { franchise_id: franchise.franchise_id, name: franchise.name },
      record: standings().find((t) => t.franchise_id === franchise.franchise_id) ?? null,
      scoring: { games: played.length, ppg: played.length ? forPts / played.length : null, opp_ppg: played.length ? agPts / played.length : null },
      roster: contracts.filter((c) => onRosterIn(c, capSeason) || (c.status === 'Active' && c.start_season > capSeason)).sort((a, b) => b.pcv - a.pcv || b.fp_cost - a.fp_cost).map(publicContract),
      dead_cap: contracts.filter((c) => c.status === 'Dead cap' && contractEnd(c) >= capSeason).map(publicContract),
      cap: {
        size: evaluation.size, roster_max: ROSTER_MAX, roster_min: ROSTER_MIN, pcv: evaluation.pcv, pcv_cap: PCV_CAP, floor: evaluation.floor,
        franchise_tier: evaluation.franchiseCount, franchise_tier_max: MAX_FRANCHISE_TIER, fp_cap: FP_CAP, fp_by_season: evaluation.fp,
        bank: bank.balance, bank_max: BANK_MAX, legal: evaluation.legal, problems: evaluation.problems, warnings: evaluation.warnings
      },
      players: stats.map((r) => publicStats(r, names)),
      games
    });
  }
  if (route === 'player' && parts[1]) {
    const player = await db.prepare('SELECT player_id, display_name, franchise_id, position FROM players WHERE player_id = ?').bind(parts[1]).first();
    if (!player) return apiJson({ error: 'No such player' }, 404);
    const line = (await playerSeasonStats(db, season)).find((r) => r.player_id === player.player_id);
    const log = (await db.prepare(`
      SELECT f.fixture_id, f.week, f.home_id, f.away_id, f.winner_id, f.home_score, f.away_score, pg.franchise_id,
        pg.pts, pg.reb, pg.ast, pg.stl, pg.blk, pg.tov, pg.fgm, pg.fga, pg.tpm, pg.tpa, pg.ftm, pg.fta
      FROM player_games pg JOIN fixtures f ON f.fixture_id = pg.fixture_id
      WHERE pg.player_id = ? AND f.season = ? AND f.status = 'Final' AND f.result_type = 'Played'
      ORDER BY f.week, f.fixture_id`).bind(player.player_id, season).all()).results ?? [];
    const contract = (await db.prepare("SELECT c.*, p.display_name FROM contracts c LEFT JOIN players p ON p.player_id = c.player_id WHERE c.player_id = ? AND c.status = 'Active' ORDER BY c.start_season DESC LIMIT 1").bind(player.player_id).first());
    const credits = (await db.prepare('SELECT COUNT(*) AS n FROM eligibility_credits c JOIN fixtures f ON f.fixture_id = c.fixture_id WHERE c.player_id = ? AND f.season = ?').bind(player.player_id, season).first())?.n ?? 0;
    return apiJson({
      season,
      player: { player_id: player.player_id, name: player.display_name, franchise_id: player.franchise_id, team: names[player.franchise_id] ?? null, position: player.position },
      stats: line ? publicStats(line, names) : null,
      eligibility: { appearances: line?.gp ?? 0, credits, needed: APPEARANCES_NEEDED },
      contract: contract ? publicContract(contract) : null,
      games: log.map((g) => {
        const opponent = g.franchise_id === g.home_id ? g.away_id : g.home_id;
        const own = g.franchise_id === g.home_id ? g.home_score : g.away_score;
        const opp = g.franchise_id === g.home_id ? g.away_score : g.home_score;
        return {
          fixture_id: g.fixture_id, week: g.week, home: g.franchise_id === g.home_id, opponent_id: opponent, opponent: names[opponent] ?? opponent,
          won: g.winner_id === g.franchise_id, score: `${own}–${opp}`,
          pts: g.pts, reb: g.reb, ast: g.ast, stl: g.stl, blk: g.blk, tov: g.tov, fgm: g.fgm, fga: g.fga, tpm: g.tpm, tpa: g.tpa, ftm: g.ftm, fta: g.fta
        };
      })
    });
  }
  return apiJson({ error: 'Not found' }, 404);
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
  if (!IMPORT_COLUMNS[kind]) return 'Choose teams, players, games, or prices.';
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
      if (!r.discord_id || !/^\d{15,22}$/.test(r.discord_id)) { problems.push(`line ${r._line}: every player needs a linked Discord account — put their discord_id (the long number from "Copy User ID")`); continue; }
      statements.push(db.prepare(
        'INSERT INTO players (player_id, display_name, discord_id, franchise_id, position, updated_at) VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(player_id) DO UPDATE SET display_name = excluded.display_name, discord_id = COALESCE(excluded.discord_id, players.discord_id), franchise_id = excluded.franchise_id, position = excluded.position, updated_at = excluded.updated_at'
      ).bind(r.player_id, r.display_name, r.discord_id || null, r.franchise_id || null, r.position || null, now));
    }
  } else if (kind === 'prices') {
    if (!header.includes('scorecard_total') && !(header.includes('tier') && header.includes('fp_cost'))) {
      return 'The prices file needs player_id plus either scorecard_total, or tier and fp_cost. Optional: season.';
    }
    const { season: current } = await leagueState(db);
    const known = new Set(((await db.prepare('SELECT player_id FROM players').all()).results ?? []).map((r) => r.player_id));
    for (const r of records) {
      if (!known.has(r.player_id)) { problems.push(`line ${r._line}: unknown player ${r.player_id || '(blank)'}`); continue; }
      const season = r.season ? Number(r.season) : current;
      if (!Number.isInteger(season) || season < 1) { problems.push(`line ${r._line}: season must be a whole number`); continue; }
      const price = priceFrom({ scorecard: r.scorecard_total || null, tier: r.tier, fp_cost: r.fp_cost });
      if (price.error) { problems.push(`line ${r._line}: ${price.error}`); continue; }
      statements.push(db.prepare(
        'INSERT INTO player_prices (player_id, season, tier, fp_cost, source, set_by, set_at) VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT(player_id, season) DO UPDATE SET tier = excluded.tier, fp_cost = excluded.fp_cost, source = excluded.source, set_by = excluded.set_by, set_at = excluded.set_at'
      ).bind(r.player_id, season, price.tier, price.fp_cost, price.source, me, now));
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
  '**How the league menu works**',
  'Type `/drew menu` (or use the pinned menu) and tap a button. Only you see DREW\'s answers.',
  '• **Report a game** — winning team\'s captain or GM: pick the game, pick who won, upload the Game Stats screenshot. Do it within 24 hours of the game time. If you lost, you don\'t need to do anything.',
  '• **Set a game time** — captains and GMs: pick the game, the day, and the time. The other team taps **Confirm time**.',
  '• **My games** — your team\'s games still to play or report.',
  '• **My stats**, **My team**, **Standings**, **League leaders** — numbers, rosters, and salaries.',
  '• **Link my gamertag** — your in-game name, so DREW can match you in screenshots. A committee member approves it.',
  '• **Offers & requests** — contract offers to accept, trades to agree to, and anything you sent that is still waiting.',
  '• **GM tools** — GMs: offer contracts, release players, propose trades. DREW checks the cap rules first.',
  '• **Draft** — who\'s on the clock. GMs make their picks there.',
  'Words: **FP** is salary (each team has 44 per season). **PCV** is a player\'s value tier (each team can have at most 90). **Played** games are games actually played, not forfeits or no-report wins.',
  'Commissioner: `/drew admin …` (post-menu, import, price, draft, staff, player, forfeit, credit, export, publish, sign, release, trade, option, season, readtest) and `/drew setup-check`.'
].join('\n');

// ---------------------------------------------------------------- router

export default {
  async scheduled(controller, env, ctx) {
    ctx.waitUntil(runTimers(env).catch((error) => console.error(`Timer run failed: ${error.message}`)));
  },

  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    if (request.method === 'GET' && url.pathname === '/health') {
      return new Response('DREW endpoint is ready.', { headers: { 'content-type': 'text/plain; charset=utf-8' } });
    }
    if (url.pathname.startsWith('/api/')) {
      try {
        return await handleApi(request, env, url);
      } catch (error) {
        console.error(`Website API failed: ${error.message}`);
        return apiJson({ error: 'Something went wrong loading league data.' }, 500);
      }
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

    if (interaction.type === 4) return gameAutocomplete(interaction, env);

    // Buttons and lists
    if (interaction.type === 3) {
      const [scope, action, ...rest] = String(interaction.data?.custom_id ?? '').split(':');
      const values = interaction.data?.values ?? [];
      const me = invokerId(interaction);
      const run = (work) => respond(ctx, interaction, async () => { await ensureSchema(requireDb(env)); return work(requireDb(env)); });
      const last = () => rest.at(-1);
      const id = () => Number(rest[0]);

      if (scope === 'menu') {
        if (action === 'gamertag') return gamertagModal(env, interaction);
        const screens = {
          report: () => menuReport(interaction, env),
          games: async () => ({ content: await myFixtures(interaction, env), components: [actionRow(btn('Report a game', 'menu:report', 1), btn('Set a game time', 'menu:time'))] }),
          time: () => menuGameTime(interaction, env),
          stats: () => menuStats(interaction, env),
          team: () => menuTeam(interaction, env),
          standings: () => menuStandings(env),
          leaders: () => menuLeaders(env),
          offers: (db) => requestsView(db, me),
          gm: () => menuGm(interaction, env),
          draft: () => menuDraft(interaction, env),
          help: async () => HELP_TEXT
        };
        // A tap on the menu itself opens a new private reply so the menu stays where it is.
        const onMenu = String(interaction.message?.content ?? '').startsWith('**League menu**');
        if (screens[action]) {
          return onMenu
            ? deferEphemeral(ctx, interaction, async () => { await ensureSchema(requireDb(env)); return screens[action](requireDb(env)); })
            : run(screens[action]);
        }
      }
      if (scope === 'rpt' && action === 'pick') {
        const fx = await gameWithNames(requireDb(env), values[0]);
        return fx ? reportModal(fx) : ephemeral('That game wasn\'t found.');
      }
      if (scope === 'gt' && (action === 'pick' || action === 'other')) {
        const db = requireDb(env);
        const fx = await gameWithNames(db, action === 'pick' ? values[0] : rest.join(':'));
        if (!fx) return ephemeral('That game wasn\'t found.');
        return gameTimeModal(fx, await userZone(db, me));
      }
      if (scope === 'look' && action === 'player') return run(() => menuStats(interaction, env, values[0]));
      if (scope === 'ldr' && action === 'cat') return run(() => menuLeaders(env, values[0]));
      if (scope === 'team' && action === 'pick') return run(() => menuTeam(interaction, env, values[0]));
      if (scope === 'team' && action === 'show') return run(() => menuTeam(interaction, env, rest.join(':')));
      if (scope === 'team' && action === 'elig') {
        return run(async () => ({ content: await eligibilityCommand(interaction, env, { franchise: rest.join(':') }), components: [actionRow(btn('Back to team', `team:show:${rest.join(':')}`))] }));
      }
      if (scope === 'gm' && action === 'offer') return run((db) => offerStart(db, me));
      if (scope === 'gm' && action === 'release') return run((db) => releaseStart(db, me));
      if (scope === 'gm' && action === 'trade') return run((db) => tradeStart(db, me));
      if (scope === 'gmo' && action === 'tier') return run((db) => offerStart(db, me, rest[0]));
      if (scope === 'gmo' && action === 'pick') return run((db) => offerPreview(db, me, values[0]));
      if (scope === 'gmo' && action === 'send') return run((db) => offerSend(env, db, me, rest.slice(0, -1).join(':'), Number(last())));
      if (scope === 'gmr' && action === 'pick') return run((db) => releasePreview(db, me, values[0]));
      if (scope === 'gmr' && ['dead', 'buy'].includes(action)) return run((db) => releaseSend(env, db, me, rest.join(':'), action === 'buy' ? 'buyout' : 'deadcap'));
      if (scope === 'gmt' && action === 'team') return run((db) => tradeCreate(db, me, values[0]));
      if (scope === 'gmt' && ['send', 'get'].includes(action)) return run((db) => tradeSelect(db, me, id(), action, values));
      if (scope === 'gmt' && action === 'submit') return run((db) => tradeSubmit(env, db, me, id()));
      if (scope === 'gmt' && action === 'cancel') {
        return run(async (db) => {
          await db.prepare("UPDATE pending_tx SET status = 'Abandoned' WHERE id = ? AND status = 'Draft' AND created_by = ?").bind(id(), me).run();
          return menuGm(interaction, env);
        });
      }
      if (scope === 'ofr' && ['accept', 'decline', 'withdraw'].includes(action)) return run(async (db) => requestsView(db, me, await offerDecision(env, db, me, id(), action)));
      if (scope === 'trd' && ['accept', 'decline', 'withdraw', 'yes', 'no'].includes(action)) return run(async (db) => requestsView(db, me, await tradeRespond(env, db, me, id(), action)));
      if (scope === 'dft') {
        if (action === 'pick') return run(() => draftPickView(interaction, env, null));
        if (action === 'tiers') return run(() => draftPickView(interaction, env, id()));
        if (action === 'tier') return run(() => draftPickView(interaction, env, id(), rest[1], Number(rest[2] ?? 0)));
        if (action === 'sel') return run(() => draftConfirmView(interaction, env, id(), values[0]));
        if (action === 'ok') return run(() => draftMakePick(interaction, env, id(), rest.slice(1).join(':')));
        if (action === 'pass') return run(() => draftPass(interaction, env));
      }
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
      if (scope === 'tx' && ['approve', 'cancel'].includes(action)) {
        return deferButton(ctx, interaction, async () => { await ensureSchema(requireDb(env)); await transactionButton(interaction, env, action, Number(rest[0])); });
      }
      if (scope === 'rv' && ['accept', 'recheck', 'reject'].includes(action)) {
        return deferButton(ctx, interaction, () => reviewButton(interaction, env, action, Number(rest[0])));
      }
      return ephemeral('This button is no longer active. Open a fresh menu with `/drew menu`.');
    }

    // Pop-up forms submitted
    if (interaction.type === 5) {
      const [scope, ...rest] = String(interaction.data?.custom_id ?? '').split(':');
      const target = rest.join(':');
      const v = modalValues(interaction);
      if (scope === 'rptmodal') return deferButton(ctx, interaction, () => disputeSubmit(interaction, env, Number(target)));
      if (scope === 'rptform') {
        return deferEphemeral(ctx, interaction, async () => { await ensureSchema(requireDb(env)); return submitReport(interaction, env, { fixture: target, winner: v.winner?.[0], screenshot: v.shot?.[0] }); });
      }
      if (scope === 'gtform') return deferEphemeral(ctx, interaction, async () => { await ensureSchema(requireDb(env)); return gameTimeFromForm(interaction, env, target); });
      if (scope === 'gtagform') return deferEphemeral(ctx, interaction, () => gamertagSet(interaction, env, { name: v.name, platform: v.platform?.[0] }));
      return ephemeral('This form is no longer active.');
    }

    if (interaction.type !== 2 || interaction.data?.name !== 'drew') {
      return ephemeral('DREW does not recognize that command.');
    }

    const { path, opts } = readCommand(interaction);
    const command = path.join(' ');

    if (env.DB) ctx.waitUntil(ensureSchema(env.DB).catch(() => {}));

    if (command === 'help') {
      // Refresh the server's command list after a deployment, and say whether Discord accepted it.
      return deferEphemeral(ctx, interaction, async () => {
        const reg = await registerCommands(env);
        const note = reg?.ok
          ? `✅ Command list refreshed (DREW ${DREW_VERSION}). If you still see old commands, restart Discord (Ctrl+R on PC, close and reopen on phone).`
          : `⚠️ Discord did not accept the command list (HTTP ${reg?.status}). ${reg?.detail ?? ''}`.trim();
        return `${HELP_TEXT}\n\n${note}`.slice(0, 1990);
      });
    }
    if (command === 'menu') return json({ type: 4, data: { ...menuMessage(), flags: EPHEMERAL, allowed_mentions: { parse: [] } } });
    if (command === 'setup-check') return runSetupCheck(interaction, env);
    if (command === 'report') return deferEphemeral(ctx, interaction, async () => { await ensureSchema(requireDb(env)); return submitReport(interaction, env, opts); });

    if (path[0] === 'admin') {
      return deferEphemeral(ctx, interaction, async () => {
        await ensureSchema(requireDb(env));
        const roles = await memberRoleNames(interaction, env);
        if (['admin forfeit', 'admin credit'].includes(command)) {
          if (!isReviewer(roles)) return 'Forfeits and credits are for the Commissioner and the League Committee.';
          return command === 'admin forfeit' ? adminForfeit(interaction, env, opts) : adminCredit(interaction, env, opts);
        }
        if (!isCommissioner(roles)) return 'Admin commands are for the Commissioner role.';
        if (command === 'admin post-menu') return adminPostMenu(interaction, env);
        if (command === 'admin price') return adminPrice(interaction, env, opts);
        if (command === 'admin draft') return adminDraft(interaction, env, opts);
        if (command === 'admin export') return adminExport(env, opts);
        if (command === 'admin sign') return adminSign(interaction, env, opts);
        if (command === 'admin release') return adminRelease(interaction, env, opts);
        if (command === 'admin trade') return adminTrade(interaction, env, opts);
        if (command === 'admin option') return adminOption(interaction, env, opts);
        if (command === 'admin season') return adminSeason(interaction, env, opts);
        if (command === 'admin publish') return adminPublish(env, opts);
        if (command === 'admin import') return adminImport(interaction, env, opts);
        if (command === 'admin readtest') return adminReadTest(interaction, env, opts);
        if (command === 'admin staff') return adminStaff(interaction, env, opts);
        if (command === 'admin player') return adminPlayer(interaction, env, opts);
        return 'Unknown admin command.';
      });
    }
    return ephemeral('That command was removed. Type `/drew menu` and use the buttons.');
  }
};
