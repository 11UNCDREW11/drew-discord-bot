const REQUIRED_ROLES = ['commissioner', 'gm', 'captain', 'freeagent', 'player'];
const REQUIRED_CHANNELS = [
  'welcome', 'rules', 'announcements', 'generalchat', 'schedule', 'standings',
  'leaguestats', 'weekly slate', 'transactions', 'gmchat', 'captainschat',
  'gamereports', 'contactcommissioner'
].map((name) => name.replace(/[^a-z0-9]/g, ''));
const EPHEMERAL = 64;
const normalizeName = (name) => name.toLowerCase().replace(/[^a-z0-9]/g, '');

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
    return 'DREW setup is incomplete. Ask the Commissioner to check the bot configuration.';
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
      return 'This setup check is available to the Commissioner role.';
    }

    const missingRoles = REQUIRED_ROLES.filter((expected) =>
      !roles.some((role) => role.name.toLowerCase().replace(/[^a-z0-9]/g, '') === expected)
    );
    const missingChannels = REQUIRED_CHANNELS.filter((expected) =>
      !channels.some((channel) => [0, 5].includes(channel.type)
        && channel.name.toLowerCase().replace(/[^a-z0-9]/g, '') === expected)
    );
    const franchiseCategoryIds = new Set(channels
      .filter((channel) => channel.type === 4
        && normalizeName(channel.name).includes('franchise')
        && normalizeName(channel.name).includes('chat'))
      .map((category) => category.id));
    const franchiseChannelCount = channels.filter((channel) =>
      [0, 5].includes(channel.type) && franchiseCategoryIds.has(channel.parent_id)
    ).length;
    const lines = ['**DREW server setup check**'];
    lines.push(missingRoles.length
      ? `Missing roles: ${missingRoles.map((name) => `\`${name}\``).join(', ')}`
      : `Roles: all ${REQUIRED_ROLES.length} required roles found.`);
    lines.push(missingChannels.length
      ? `Missing text channels: ${missingChannels.map((name) => `\`#${name}\``).join(', ')}`
      : `Text channels: all ${REQUIRED_CHANNELS.length} required channels found.`);
    lines.push(franchiseChannelCount === 8
      ? 'Franchise chats: all 8 text channels found under a Franchise Chats category.'
      : `Franchise chats: found ${franchiseChannelCount} text channels under a Franchise Chats category; expected 8.`);
    lines.push('This check reads role and channel names only. It does not inspect message history or change league data.');
    return ephemeral(lines.join('\n'));
    return lines.join('\n');
  } catch (error) {
    console.error(`Setup check could not read server configuration: ${error.message}`);
    return ephemeral('DREW could not complete the setup check. Ask the Commissioner to review its server access and configuration.');
    return 'DREW could not complete the setup check. Ask the Commissioner to review its server access and configuration.';
  }
}

async function finishDeferredSetupCheck(interaction, env) {
  let content = 'DREW could not complete the setup check. Ask the Commissioner to review its server access and configuration.';
  try {
    content = await runSetupCheck(interaction, env);
  } catch (error) {
    console.error(`Deferred setup check failed: ${error.message}`);
  }

  const url = `https://discord.com/api/v10/webhooks/${interaction.application_id}/${interaction.token}/messages/@original`;
  try {
    const response = await fetch(url, {
      method: 'PATCH',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ content })
    });
    if (!response.ok) {
      console.error(`Setup check result could not be delivered; Discord returned HTTP ${response.status}.`);
    }
  } catch (error) {
    console.error(`Setup check result delivery failed: ${error.message}`);
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
    if (subcommand === 'setup-check') {
      // Acknowledge within Discord's short initial-response deadline, then do
      // the slower role/channel lookups and edit the deferred response.
      ctx.waitUntil(finishDeferredSetupCheck(interaction, env));
      return json({ type: 5, data: { flags: EPHEMERAL } });
    }
    return ephemeral('Choose `/drew help` or `/drew setup-check`.');
  }
};
