import 'dotenv/config';
import { ChannelType, Client, GatewayIntentBits, MessageFlags } from 'discord.js';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const token = process.env.DISCORD_BOT_TOKEN;
if (!token) throw new Error('Set DISCORD_BOT_TOKEN in .env before starting DREW.');

const here = path.dirname(fileURLToPath(import.meta.url));
const layout = JSON.parse(await readFile(path.join(here, '../config/server-layout.json'), 'utf8'));
const normalize = (value) => value.toLowerCase().replace(/[^a-z0-9]/g, '');
const client = new Client({ intents: [GatewayIntentBits.Guilds] });

client.once('ready', () => {
  console.log(`DREW is online as ${client.user.tag}.`);
});

client.on('interactionCreate', async (interaction) => {
  if (!interaction.isChatInputCommand() || interaction.commandName !== 'drew') return;
  if (!interaction.inGuild()) {
    await interaction.reply({ content: 'Use DREW in the league server.', flags: MessageFlags.Ephemeral });
    return;
  }

  const action = interaction.options.getSubcommand();
  if (action === 'help') {
    await interaction.reply({
      content: [
        '**DREW setup build**',
        '`/drew setup-check` — Commissioner-only check for the league roles and channels.',
        '`#weekly-slate` — the actionable matchups and deadlines for the current game week.',
        '`#schedule` — the broader season calendar and date changes.',
        '`#game-reports` — the public route for completed-game report status; evidence workflows are not enabled yet.',
        'DREW does not currently create standings, player stats, GP, forfeits, or eligibility records.'
      ].join('\n'),
      flags: MessageFlags.Ephemeral
    });
    return;
  }

  const isCommissioner = interaction.member.roles.cache.some((role) => normalize(role.name) === 'commissioner');
  if (!isCommissioner) {
    await interaction.reply({ content: 'This setup check is available to the Commissioner role.', flags: MessageFlags.Ephemeral });
    return;
  }

  const roles = interaction.guild.roles.cache;
  const channels = interaction.guild.channels.cache;
  const missingRoles = layout.requiredRoles.filter((expected) =>
    !roles.some((role) => normalize(role.name) === normalize(expected))
  );
  const missingChannels = layout.requiredTextChannels.filter((expected) =>
    !channels.some((channel) => normalize(channel.name) === normalize(expected)
      && [ChannelType.GuildText, ChannelType.GuildAnnouncement].includes(channel.type))
  );

  const lines = ['**DREW server setup check**'];
  lines.push(missingRoles.length
    ? `Missing roles: ${missingRoles.map((name) => `\`${name}\``).join(', ')}`
    : `Roles: all ${layout.requiredRoles.length} required roles found.`);
  lines.push(missingChannels.length
    ? `Missing text channels: ${missingChannels.map((name) => `\`#${name}\``).join(', ')}`
    : `Text channels: all ${layout.requiredTextChannels.length} required channels found.`);
  lines.push('This check matches channel/role names only. It does not inspect permissions or change league data.');
  await interaction.reply({ content: lines.join('\n'), flags: MessageFlags.Ephemeral });
});

await client.login(token);
