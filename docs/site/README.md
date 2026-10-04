# ffl CLI website

A static, responsive site positioning ffl as **Transfer for humans and agents**.
Source and build output stay under `docs/site`; the site does not use the CLI's download-page templates.

## Develop and build

Requires Node.js 22.12+ or 24 and npm.

```sh
cd docs/site
npm ci
npm run dev
# Production output: docs/site/dist
npm run build
npm run preview
```

The build uses relative asset URLs (`--base=./`), so the same output works at a domain root, a GitHub project URL such as `https://nuwainfo.github.io/ffl/`, or another subdirectory. Serve the output over HTTP(S), not `file://`.

## Deploy to GitHub Pages

1. In the repository's **Settings → Pages**, select **GitHub Actions** as the source.
2. Run **Deploy CLI site to GitHub Pages** from the Actions tab.
3. The workflow builds and publishes only `docs/site/dist`. Its deployment output gives the actual URL.

The workflow is manual so commits do not automatically replace an existing Pages site. No deployment has to be performed to develop or review this site. You can also upload the contents of `dist/` to any static host.

## Languages and behavior

- i18next resources: `src/locales/en.json`, `zh_hans.json`, `zh_hant.json`.
- Language precedence: `?lang=` → stored choice → browser language → English. Accepts aliases such as `zh-TW` and `zh-CN`; HTML uses standard `zh-Hant` / `zh-Hans` tags.
- The switcher updates content, accessible labels, page title, description, and share metadata. Choice persists when browser storage is available.
- All runtime assets and translations are bundled locally. No CDN scripts, external fonts, analytics, or API keys.
- Static English content and links remain usable without JavaScript. Interactive examples, copy buttons, and language switching need JavaScript.

## Verify

```sh
npx playwright install chromium
npm test
```

Tests build the production site and serve it under `/ffl/`, exercising all three languages, mobile layouts, command selection/copying, fallback behavior, and local links. On a machine with Microsoft Edge installed, use `FFL_SITE_BROWSER=msedge` to avoid a browser download. For PowerShell: `$env:FFL_SITE_BROWSER='msedge'; npm test`.

## Content basis and positioning

The promise is a practical handoff: a person opens a browser link; an agent can fetch the same artifact through the CLI or companion MCP server. Local models, generated outputs, and CI batches do not need cloud-storage staging. ffl remains the transfer engine, while the caller owns orchestration and process lifetime.

Claims were checked against source and releases through v4.2.2:

| Claim                                                          | Source of truth                                                                                                                                                                                                     |
| -------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Native TCP/QUIC, browser WebRTC, fallback/resume               | `bases/P2P.py`, `bases/Download.py`, `bases/WebRTC.py`; [v4.2.2](https://github.com/nuwainfo/ffl/releases/tag/v4.2.2)                                                                                               |
| Explicit LAN mode; HTTP link, not default behavior             | `bases/tunnels/LAN.py`, `bases/Settings.py`, `addons/Tunnels.py`; [v4.2.1](https://github.com/nuwainfo/ffl/releases/tag/v4.2.1)                                                                                     |
| Only new, settled direct child folders; append-only collection | `bases/Collection.py`, `bases/Share.py`, `CollectionDownloadFollower` in `bases/Download.py`; [v4.2.0](https://github.com/nuwainfo/ffl/releases/tag/v4.2.0)                                                         |
| JSON output, hooks, VFS                                        | `bases/Share.py`, `bases/Hook.py`, `bases/VFS.py`; [embedded guide](https://github.com/nuwainfo/ffl/wiki/Embedded-Mode-%26-Event-Hooks), [VFS guide](https://github.com/nuwainfo/ffl/wiki/VFS-Implementation-Guide) |
| MCP is a companion integration                                 | [ffl-mcp](https://github.com/nuwainfo/ffl-mcp)                                                                                                                                                                      |
| Install commands and build platforms                           | `dist/install.sh`, `dist/install.ps1`, release assets                                                                                                                                                               |

Avoid absolute speed, anonymity, unlimited relay, or guaranteed-delivery claims. E2EE is opt-in, metadata remains visible, and ordinary internet sharing may use signaling/relay infrastructure. Direct sharing requires sender availability. `--upload` is separate and requires an account and addon. The site distinguishes these conditions near the relevant benefit, not just in the FAQ.
