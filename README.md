# DREW Discord Bot — first build

DREW is the bot for the separate AUTOBOT league. This first build is intentionally limited to connecting to the league server, providing a help command, and checking the expected server roles and text channels. It does not write standings, game reports, player stats, forfeits, or playoff-eligibility records.

## Channel purposes

- `#schedule`: season calendar, active-week dates, make-up deadline, playoff dates, and Commissioner schedule changes.
- `#weekly-slate`: the current week's actionable fixtures and their coordination/report deadlines. With 8 franchises and 5 fixtures per franchise each week, a full slate contains 20 unique fixtures; each fixture is listed once.
- `#game-reports`: completed-game report submissions and status. The eventual workflow will validate the report and evidence, collect opponent confirmation, and send exceptions to the Commissioner before final records change.

The user-built structure covers the main launch needs. An optional `#free-agent-board` could help free agents announce availability and franchises find players, but it is not required if `#transactions` or franchise chats will handle that. Keep `#contact-commissioner` private for the reporter and staff, using a private ticket/command workflow rather than posting disputes or locker-room screenshots publicly.

## Prerequisites

- Node.js 24.17 or newer.
- A Discord application and bot created in the Discord Developer Portal.
- The bot invited to the league server with the `bot` and `applications.commands` scopes. Grant only the channel and command access it needs; do not grant Administrator.
- The bot needs View Channels, Send Messages, and Use Application Commands in channels where it responds. Only the `Guilds` gateway intent is used; Message Content, Presence, and member-list intents are not enabled.

## Configure and run

1. Copy `.env.example` to `.env`.
2. Fill in the bot token, application ID, and league server (guild) ID in `.env`. Keep `.env` private and never paste the token into chat.
3. Install the dependencies from this folder with `npm install`.
4. Publish the server-only slash command with `npm run register`.
5. Start DREW with `npm start` and run `/drew help` or `/drew setup-check` in the server.

`/drew setup-check` is Commissioner-role-only and checks the required role/channel names in `config/server-layout.json`. Discord normalizes spaces and punctuation, so a displayed name such as `#general-chat` matches the supplied `#general chat` description. If a channel is named differently, update the config to the exact intended name before running the check.

## Build sequence

1. Connect DREW and validate server layout.
2. Confirm channel permissions and role-based visibility.
3. Define fixture IDs and the weekly-slate publication flow.
4. Build game-report submission, opponent confirmation, evidence handling, and Commissioner review.
5. Choose and implement the authoritative database, audit history, exports/backups, and participant views.
6. Add standings, stats, transactions, and eligibility views only after the underlying records are validated.

The AUTOBOT Rulebook remains authoritative. Keep Commissioner-only simulation documents and private evidence out of participant-facing channels.
