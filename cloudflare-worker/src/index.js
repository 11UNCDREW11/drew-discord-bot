const REQUIRED_ROLES = ['commissioner', 'gm', 'captain', 'freeagent', 'player'];
const REQUIRED_CHANNELS = [
  'welcome', 'rules', 'announcements', 'generalchat', 'schedule', 'standings',
  'leaguestats', 'weekly slate', 'transactions', 'gmchat', 'captainschat',
  'franchisechat1', 'franchisechat2', 'franchisechat3', 'franchisechat4',
  'franchisechat5', 'franchisechat6', 'franchisechat7', 'franchisechat8',
  'gamereports', 'contactcommissioner'
].map((name) => name.replace(/[^a-z0-9]/g, ''));
const EPHEMERAL = 64;

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
  if (!signature || !timestamp || !publicKey) return false;
  const timestampSeconds = Number(timestamp);
  if (!Number.isFinite(timestampSeconds) || Math.abs(Date.now() / 1000 - timestampSeconds) > 300) return false;
  try {
    const key = await crypto.subtle.importKey('raw', hexToBytes(publicKey), { name: 'Ed25519' }, false, ['verify']);
    return await crypto.subtle.verify(
      { name: 'Ed25519' },
      key,
      hexToBytes(signature),
      new TextEncoder().encode(timestamp + body)
    );
  } catch {
    return false;
  }
}

const commandDefinitions = [
  {
    type: 1,
    name: 'drew',
    description: 'DREW league assistant',
    options: [
      { type: 1, name: 'help', description: 'Show DREW command status and channel purposes' },
      { type: 1, name: 'setup-check', description: 'Commissioner-only check of league roles and channels' }
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

function ephemeral(content) {
  return json({ type: 4, data: { content, flags: EPHEMERAL } });
}

async function discordGet(path, token) {
  const response = await fetch(`https://discord.com/api/v10${path}`, {
    headers: { authorization: `Bot ${token}` }
  });
  if (!response.ok) throw new Error(`Discord API returned HTTP ${response.status}`);
  return response.json();
}

async function runSetupCheck(interaction, env) {
  if (!env.DISCORD_BOT_TOKEN || !env.DISCORD_GUILD_ID) {
    return ephemeral('DREW setup is incomplete. Ask the Commissioner to check the bot configuration.');
  }
  try {
    const [roles, channels] = await Promise.all([
      discordGet(`/guilds/${env.DISCORD_GUILD_ID}/roles`, env.DISCORD_BOT_TOKEN),
      discordGet(`/guilds/${env.DISCORD_GUILD_ID}/channels`, env.DISCORD_BOT_TOKEN)
    ]);
    const commissioner = roles.find((role) => role.name.toLowerCase().replace(/[^a-z0-9]/g, '') === 'commissioner');
    const memberRoleIds = interaction.member?.roles ?? [];
    if (!commissioner || !memberRoleIds.includes(commissioner.id)) {
      return ephemeral('This setup check is available to the Commissioner role.');
    }

    const missingRoles = REQUIRED_ROLES.filter((expected) =>
      !roles.some((role) => role.name.toLowerCase().replace(/[^a-z0-9]/g, '') === expected)
    );
    const missingChannels = REQUIRED_CHANNELS.filter((expected) =>
      !channels.some((channel) => [0, 5].includes(channel.type)
        && channel.name.toLowerCase().replace(/[^a-z0-9]/g, '') === expected)
    );
    const lines = ['**DREW server setup check**'];
    lines.push(missingRoles.length
      ? `Missing roles: ${missingRoles.map((name) => `\`${name}\``).join(', ')}`
      : `Roles: all ${REQUIRED_ROLES.length} required roles found.`);
    lines.push(missingChannels.length
      ? `Missing text channels: ${missingChannels.map((name) => `\`#${name}\``).join(', ')}`
      : `Text channels: all ${REQUIRED_CHANNELS.length} required channels found.`);
    lines.push('This check reads role and channel names only. It does not inspect message history or change league data.');
    return ephemeral(lines.join('\n'));
  } catch (error) {
    console.error(`Setup check could not read server configuration: ${error.message}`);
    return ephemeral('DREW could not complete the setup check. Ask the Commissioner to review its server access and configuration.');
  }
}

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

    if (interaction.type !== 2 || interaction.data?.name !== 'drew') {
      return ephemeral('DREW does not recognize that command.');
    }

    const subcommand = interaction.data.options?.[0]?.name;
    if (subcommand === 'help') {
      return ephemeral([
        '**DREW setup build**',
        '`/drew setup-check` — Commissioner-only check for the league roles and channels.',
        '`#weekly-slate` — the actionable matchups and deadlines for the current game week.',
        '`#schedule` — the broader season calendar and date changes.',
        '`#game-reports` — the route for completed-game report status; evidence workflows are not enabled yet.',
        'DREW does not currently create standings, player stats, GP, forfeits, or eligibility records.'
      ].join('\n'));
    }
    if (subcommand === 'setup-check') return runSetupCheck(interaction, env);
    return ephemeral('Choose `/drew help` or `/drew setup-check`.');
  }
};

