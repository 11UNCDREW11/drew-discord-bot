import 'dotenv/config';
import { REST, Routes, SlashCommandBuilder } from 'discord.js';

const { DISCORD_BOT_TOKEN, DISCORD_APPLICATION_ID, DISCORD_GUILD_ID } = process.env;
if (!DISCORD_BOT_TOKEN || !DISCORD_APPLICATION_ID || !DISCORD_GUILD_ID) {
  throw new Error('Set DISCORD_BOT_TOKEN, DISCORD_APPLICATION_ID, and DISCORD_GUILD_ID in .env first.');
}

const commands = [
  new SlashCommandBuilder()
    .setName('drew')
    .setDescription('DREW league assistant')
    .addSubcommand((subcommand) => subcommand
      .setName('help')
      .setDescription('Show DREW command status and channel purposes'))
    .addSubcommand((subcommand) => subcommand
      .setName('setup-check')
      .setDescription('Commissioner-only check of required league roles and channels'))
    .toJSON()
];

const rest = new REST({ version: '10' }).setToken(DISCORD_BOT_TOKEN);
await rest.put(Routes.applicationGuildCommands(DISCORD_APPLICATION_ID, DISCORD_GUILD_ID), { body: commands });
console.log('Registered DREW commands for the configured Discord server.');
