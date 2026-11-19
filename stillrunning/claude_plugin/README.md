# stillrunning shield

A side panel for Claude Code that shows what [stillrunning](https://pypi.org/project/stillrunning/) checked, blocked and held for approval, each with a plain-English reason. It also shows whether the stillrunning hook is switched on, what the last scan of the current folder found, and the known vulnerabilities (CVEs) in packages already installed. Type `/shield` to open it.

The panel only reads. It runs the `stillrunning` command (`shield --json`, `panel --json`, `cve --json`) and draws what comes back. It sends nothing anywhere. The one network call is the "Refresh CVE data" button, which runs `stillrunning cve --refresh`.

## Requirements

- `pip install stillrunning` (2.14.0 or later)
- The Claude Code hook switched on: `stillrunning --hook-claude-code`

## Install

### With stillrunning (recommended)

The panel ships inside the stillrunning pip package (2.14.3 or later):

```
pip install -U stillrunning
stillrunning --hook-claude-code
```

Restart Claude Code, then type `/shield`. `stillrunning --hook-claude-code --no-panel` installs the hook without the panel; `stillrunning --uninstall-hook-claude-code` removes both.

### From this repository

At the prompt of a Claude Code terminal session:

```
/plugin install stillrunning-shield --marketplace johhnyg/stillrunning-shield
```

Answer `y` to add the marketplace, then press Enter to choose the user scope.

From a shell:

```
claude plugin install stillrunning-shield --marketplace johhnyg/stillrunning-shield
```

In the desktop app, where `/plugin` does not run: click + next to the prompt box, then Plugins, then Add marketplace with `johhnyg/stillrunning-shield`, then Add plugin.

## License

MIT
