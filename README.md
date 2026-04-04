# StillRunning

Lightweight process monitor with Telegram alerts. Watches your processes, restarts crashes, monitors system resources, and sends you alerts.

## Features

- **Process Watchdog**: Auto-restarts crashed screen sessions
- **Resource Monitoring**: CPU, memory, disk usage alerts
- **Per-Process Memory**: Alerts when individual processes exceed thresholds
- **Log Rotation**: Auto-archives logs when they exceed size limits
- **Health File Monitoring**: Alerts when your app stops updating its heartbeat file
- **Telegram Alerts**: Get notified instantly when something breaks
- **Telegram Commands**: Text "status" to get a live summary
- **Daily Heartbeat**: Receive a daily health summary
- **Restart Limits**: Disables processes after 3 consecutive failures to prevent restart loops

## Quick Start

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

## Manual Installation

```bash
pip install stillrunning
```

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

## How It Works

StillRunning runs as a background process and:
- Checks if your screen sessions are alive every 30 seconds
- Restarts crashed processes automatically
- Monitors CPU/memory/disk every 60 seconds
- Sends Telegram alerts when thresholds are exceeded (with 1-hour cooldown to prevent spam)
- Archives log files when they exceed size limits
- Sends a daily heartbeat summary

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
