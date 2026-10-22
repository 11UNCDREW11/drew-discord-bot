# DREW on Cloudflare Workers (free temporary setup)

This variant receives Discord slash-command interactions over HTTP. It does not keep a Gateway connection open. DREW will not show an online presence in the member list, but its slash commands can respond while the Worker is available. Use slash commands for future screenshot submissions; this version cannot watch ordinary channel messages.

## What it does

- Responds to `/drew help`.
- Responds to Commissioner-only `/drew setup-check` by checking the required role and channel names through the Discord API.
- Registers the guild slash commands when Discord validates the configured interaction endpoint with a signed PING.
- Does not read message history or modify league records.

## Cloudflare Workers Builds setup

1. In Cloudflare, create a Worker from the private GitHub repository `drew-discord-bot`.
2. Set the project root directory to `cloudflare-worker`. Set the build command to `npm install` and use the default deploy command `npx wrangler deploy`.
3. Add these runtime variables in Worker Settings > Variables and Secrets:
   - `DISCORD_APPLICATION_ID` — the app's Application ID from Discord General Information.
   - `DISCORD_GUILD_ID` — your league server ID.
   - `DISCORD_PUBLIC_KEY` — the app's Public Key from Discord General Information.
4. Add `DISCORD_BOT_TOKEN` as a **Secret**, never as a normal variable or GitHub file.
5. Deploy and copy the Worker URL. In Discord Developer Portal > General Information, set Interaction Endpoint URL to `<Worker URL>/interactions` and save. Discord sends a signed PING to validate it; DREW replies and registers its slash commands.
6. In Discord, run `/drew help` to confirm it responds.

Use Workers Free only for development and early testing. Cloudflare currently lists a 100,000-request daily limit and 10 ms CPU time per invocation for the free plan. Monitor service availability and move to a paid/reliable host before the league depends on DREW for official live records.

