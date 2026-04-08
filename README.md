# StillRunning

Lightweight process monitor with auto-restart, Telegram alerts, and live dashboard. Watches your processes, restarts crashes, monitors system resources, and sends you alerts.

## How It Works

1. **Pay at [stillrunning.io](https://stillrunning.io)** — Basic ($29/mo) or AI tier ($49/mo)
2. **Get your token via email** — arrives instantly after checkout
3. **Run one command on your server**:
   ```bash
   curl -sSL https://stillrunning.io/install | python3 - --token YOUR_TOKEN
   ```
4. **Dashboard goes live** — yourname.stillrunning.io shows all your processes within 60 seconds

## Features

- **Process Watchdog**: Auto-restarts crashed screen sessions, systemd services, PM2 processes
- **Live Dashboard**: See all your processes at yourname.stillrunning.io
- **Resource Monitoring**: CPU, memory, disk usage alerts
- **Per-Process Memory**: Alerts when individual processes exceed thresholds
- **Log Rotation**: Auto-archives logs when they exceed size limits
- **Health File Monitoring**: Alerts when your app stops updating its heartbeat file
- **Telegram Alerts**: Get notified instantly when something breaks
- **Telegram Commands**: Text "status" to get a live summary
- **Daily Heartbeat**: Receive a daily health summary
- **Restart Limits**: Disables processes after 3 consecutive failures to prevent restart loops

### AI Tier Adds

- **AI Crash Diagnosis**: Claude analyzes crash logs and explains what went wrong
- **Fix Suggestions**: Get code fix suggestions sent to Telegram with approve/reject buttons
- **Daily Health Audit**: Automated code quality and infrastructure review every morning
- **Pattern Detection**: Learns from your crash history to predict and prevent issues

## Shield — Intelligent Attack Protection

Shield monitors SSH brute force attacks and automatically blocks malicious IPs.

### Basic Tier (included free)
- SSH failed login counter (reads /var/log/auth.log)
- Automatic fail2ban integration after 10 failed attempts
- Security grade A/B/C/D based on attack volume
- Daily security summary in Telegram heartbeat

### AI Tier (intelligent protection)
- Intelligent threat scoring: LOW, MEDIUM, HIGH, REPEAT offender detection
- Tiered punishment: fail2ban for LOW, iptables 24h for MEDIUM, permanent ban for HIGH/REPEAT
- AbuseIPDB reporting for HIGH+ threats (requires API key)
- Claude Haiku pattern analysis every 50 attacks
- Shared threat network: every customer protects every other customer
- Pre-emptive blocking from shared blocklist

## Multi-Server Support

Monitor multiple servers from one account. Each server gets its own token and appears on your unified dashboard.

**Basic tier**: Up to 3 servers
**AI tier**: Unlimited servers

Add a new server to your account:
```bash
stillrunning --add-server --token YOUR_CUSTOMER_TOKEN --name my-new-server
```

This generates a new server token. Run the install command with that token on your new server.

## Telegram Two-Way Control (AI tier)

AI tier customers can text their Telegram bot to control their servers:

**Commands:**
- `status` — full system status in plain English
- `restart [process]` — restart a named process (must be in config)
- `logs [process]` — view last 20 lines of process log (sanitized)
- `shield` — Shield security summary
- `help` — list available commands

**AI Chat (AI tier only):**
Any non-command message routes to Claude Haiku with full system context. Ask questions in plain English:
- "Why did my API server crash?"
- "Is my disk usage concerning?"
- "What should I check first?"

Rate limited to 20 messages per hour. All log content is sanitized before sending to AI.

## Shield Security — Log Sanitization

When AI crash diagnosis analyzes your logs, all potential secrets are automatically redacted:
- API keys (Anthropic, Stripe, Bearer tokens)
- Passwords and secrets in config format
- Long hex strings (common secret format)

This happens automatically — you don't need to configure anything.

## Quick Start

```bash
curl -sSL https://stillrunning.io/install | python3 - --token YOUR_TOKEN
```

The installer will:
1. Validate your token with stillrunning.io
2. Auto-detect running screen sessions, systemd services, and PM2 processes
3. Generate `stillrunning.yaml` in your current directory
4. Start pushing status to your dashboard every 30 seconds

## Self-Hosted (Free)

If you prefer to self-host without a dashboard:

```bash
pip install stillrunning
stillrunning --setup
```

The setup wizard will:
1. Scan for running screen sessions and systemd services
2. Detect log files in your working directory
3. Ask for your app name and Telegram credentials
4. Generate `stillrunning.yaml` automatically
5. Start monitoring

## Manual Configuration

Create `stillrunning.yaml`:

```yaml
app_name: "MyApp"
working_dir: "/home/user/myapp"

telegram_bot_token: "123456789:ABCdefGHI..."
telegram_chat_id: "987654321"

processes:
  - name: "api"
    screen: "api"
    script: "api.py"
  - name: "worker"
    screen: "worker"
    script: "worker.py"

log_files:
  - path: "app.log"
    max_mb: 10
    keep_archives: 5

health_file: "status.json"
health_max_age_sec: 180

thresholds:
  cpu_percent: 85
  mem_percent: 85
  disk_percent: 85
  process_mem_mb: 500
```

Run:

```bash
screen -dmS stillrunning stillrunning
```

## Telegram Setup

1. Create a bot: Message [@BotFather](https://t.me/BotFather) and send `/newbot`
2. Copy the bot token
3. Get your chat ID: Message [@userinfobot](https://t.me/userinfobot) and send `/start`
4. Add both to your config

## Telegram Commands

Text these to your bot:
- `status` - Get live process and resource status
- `help` - Show available commands
- `enable all` - Re-enable disabled processes

## Configuration Reference

| Field | Default | Description |
|-------|---------|-------------|
| `app_name` | "StillRunning" | Name shown in alerts |
| `working_dir` | current dir | Where your scripts live |
| `telegram_bot_token` | - | From @BotFather |
| `telegram_chat_id` | - | Your Telegram user ID |
| `processes` | [] | List of processes to monitor |
| `log_files` | [] | List of logs to auto-rotate |
| `health_file` | null | File to monitor for freshness |
| `health_max_age_sec` | 180 | Alert if health file older than this |
| `thresholds.cpu_percent` | 85 | CPU alert threshold |
| `thresholds.mem_percent` | 85 | Memory alert threshold |
| `thresholds.disk_percent` | 85 | Disk alert threshold |
| `thresholds.process_mem_mb` | 500 | Per-process memory threshold |
| `intervals.process_check_sec` | 30 | How often to check processes |
| `intervals.resource_check_sec` | 60 | How often to check resources |
| `intervals.heartbeat_sec` | 86400 | Daily heartbeat interval |
| `restart_cooldown_sec` | 120 | Minimum time between restarts |
| `max_consecutive_failures` | 3 | Disable process after this many failures |

## Requirements

- Linux (uses `/proc/stat`, `/proc/meminfo`, `screen`, `pgrep`)
- Python 3.10+
- PyYAML

## License

MIT
