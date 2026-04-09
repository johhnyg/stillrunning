# stillrunning

**Your automated systems, monitored and self-healing.**

stillrunning is a lightweight agent that watches your automated systems, restarts crashes automatically, and tells you exactly what happened — in plain English.

Built for indie hackers, solo founders, and small teams who run automated systems and want to know the second something breaks.

## What it does

- Watches your processes every 30 seconds
- Restarts crashes automatically — back online before you notice
- Sends you an alert the moment something goes wrong
- Answers your questions about what happened — in plain English
- Sends a Monday morning summary of your whole week
- Protects you from new security threats automatically

## Who it's for

- You run a scraper that sometimes crashes and find out the next morning
- You have a cron job your business depends on and want to know the second it fails
- You built something cool and want it to stay running while you sleep

## Install in 30 seconds

### Linux / Mac / Raspberry Pi

```bash
pip install stillrunning
stillrunning --setup
```

Follow the prompts. Takes about 2 minutes. You'll get a confirmation email when it's ready.

### Windows

```powershell
iwr -useb https://stillrunning.io/install.ps1 | iex
```

### Docker

```bash
docker run -d --name stillrunning \
  -e TOKEN=your_token \
  -e ALERT_EMAIL=you@example.com \
  johhnyg/stillrunning:latest
```

## What happens after install

- Within 30 seconds you get a confirmation email or Telegram message
- Your dashboard goes live at yourname.stillrunning.io
- If anything crashes you get an alert within 30 seconds
- Reply to any alert to ask questions — the AI answers from your live data
- Every Monday morning you get a summary of the week

## Commands

| Command | What it does |
|---------|--------------|
| `stillrunning --setup` | First time setup wizard |
| `stillrunning --diagnose` | Instant health check — emails you the report |
| `stillrunning --reconfigure` | Change your alert method or email |
| `stillrunning --status` | Show current status in terminal |

## Pricing

**Free** — pip install, open source, 5 security scans/month

**Basic** — $29/mo — hosted dashboard, weekly reports, threat protection

**AI** — $49/mo — AI crash diagnosis, reply to alerts, pattern detection

Full details at [stillrunning.io/pricing](https://stillrunning.io/pricing)

## Questions?

Reply to any alert email — the AI will answer.

Or email bitbot9000@gmail.com directly.

---

Built from an iPhone. Running on a $6 server. Available everywhere.
