# ffl CLI website

A static, responsive site for **Transfer for humans and agents**, built around the README's
"digital courier" idea: a file handoff is a parcel with a waybill. It is published to GitHub Pages
automatically; see [Deploy](#deploy).

## What's on the page

- **Explainer film.** A 40-second film drawn in SVG and driven by one GSAP timeline
  (`src/film.js`). It plays on the page with chapters, a pause button, a stage title that opens each
  chapter, a caption, and a text transcript, and it is translated like the rest of the page. The
  same timeline exports to MP4.
- **Identity.** A routing-ultramarine field at the top, white label stock, ballpoint-ink text, and
  a stamp red kept for "Delivered". Archivo (variable width) and Martian Mono, bundled locally via
  Fontsource; no CDN, external fonts, analytics, or API keys.
- **Viewer choices.** Theme (match system, light, dark) and page color (blue, green, violet,
  graphite). Both are remembered in the browser when storage is available and applied before first
  paint.
- **Honest copy.** Caveats stay next to their claims: opt-in E2EE, visible metadata, the sender
  must stay online, LAN links use HTTP, receipts need an account.

## Film script

| Chapter | Time | What happens |
| --- | --- | --- |
| The detour | 0–6.5s | Upload, wait, share, download, clean up through a cloud bucket. Crossed out. |
| One command | 6.5–13s | `ffl ./checkpoint --e2ee` prints a waybill: link, contents, route, encryption. |
| To a person | 13–19.5s | The link opens in a browser; WebRTC transfer; checksum verified. |
| To an agent | 19.5–26.5s | `handoff.json` passes the link to worker-b; `ffl download --resume`; real hook event names; the job continues. |
| Your route | 26.5–33.5s | Direct path blocked; HTTPS relay carries an encrypted parcel. |
| Delivered | 33.5–40s | The stamp lands; end card with the install command. |

With `prefers-reduced-motion`, the film doesn't autoplay; it shows the "Delivered" frame until
someone presses Play.

## Develop, test, export

Requires Node.js 22.12+ or 24.

```sh
cd docs/site
npm ci
npm run dev
npm run build          # -> dist/, relative asset URLs, deploy anywhere
npm run preview
```

For quick source review without Vite, `python -m http.server` also works after `npm ci`: the page
includes an import map for its installed dependencies.

```sh
npx playwright install chromium
npm test
# Windows with Edge installed: $env:FFL_SITE_BROWSER='msedge'; npm test
# Port 4174 busy: $env:FFL_SITE_PORT=4175; npm test
```

Tests build the production site and serve it under `/ffl/`, covering all three languages, layouts
from 1440px to 320px, the film controls and stage titles, theme and color choices, tabs, and copy
buttons.

Export the film (requires `ffmpeg` on PATH):

```sh
npm run build
npm run film -- --lang en,zh_hant,zh_hans          # film-out/ffl-explainer-<lang>.mp4
npm run film -- --lang en --theme dark --fps 60
```

The exporter loads `?film=record`, seeks the timeline frame by frame through `window.fflFilm`, and
pipes PNG frames to ffmpeg (H.264, 1920×1080), about a minute per language at 30 fps. Output is
ignored by git; upload the MP4 to a release or the README.

## Languages

`?lang=` → stored choice → browser language → English. Accepts aliases such as `zh-TW` and
`zh-CN`; HTML uses `zh-Hant` / `zh-Hans`. Resources are in `src/locales/{en,zh_hans,zh_hant}.json`,
including every word inside the film.

## Deploy

`.github/workflows/cli-site-pages.yml` runs on every push to `main` that touches `docs/site/`
(and can be started by hand from the Actions tab). It installs dependencies, runs the Playwright
tests, builds, and publishes `docs/site/dist` to GitHub Pages. A failing test stops the deploy.

One-time setup: in the repository's **Settings → Pages**, set **Source** to **GitHub Actions**.
The site is then served at `https://<owner>.github.io/<repo>/` (for this repository,
`https://nuwainfo.github.io/ffl/`).
