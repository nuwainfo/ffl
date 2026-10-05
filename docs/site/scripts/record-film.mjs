// Render the explainer film to MP4, frame by frame, from the built site.
//
//   npm run build && npm run film -- [--lang en,zh_hant,zh_hans] [--fps 30] [--theme light|dark]
//
// Needs ffmpeg on PATH. Output: film-out/ffl-explainer-<lang>.mp4
import { spawn } from "node:child_process";
import { mkdirSync } from "node:fs";
import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { extname, join, resolve } from "node:path";
import { chromium } from "@playwright/test";

const args = Object.fromEntries(
  process.argv
    .slice(2)
    .join(" ")
    .split("--")
    .filter(Boolean)
    .map((pair) => pair.trim().split(/\s+/)),
);
const languages = (args.lang || "en").split(",");
const fps = Number(args.fps || 30);
const theme = args.theme || "light";
const root = resolve("dist");
const outDir = resolve("film-out");
mkdirSync(outDir, { recursive: true });

const types = { ".html": "text/html", ".js": "text/javascript", ".css": "text/css", ".svg": "image/svg+xml", ".woff2": "font/woff2" };
const server = createServer(async (request, response) => {
  const path = new URL(request.url, "http://x").pathname;
  try {
    const body = await readFile(join(root, path === "/" ? "index.html" : path));
    response.writeHead(200, { "content-type": types[extname(path) || ".html"] || "application/octet-stream" });
    response.end(body);
  } catch {
    response.writeHead(404).end();
  }
}).listen(0, "127.0.0.1");
await new Promise((ready) => server.once("listening", ready));
const base = `http://127.0.0.1:${server.address().port}/`;

const browser = await chromium.launch({ channel: process.env.FFL_SITE_BROWSER || undefined });
for (const lang of languages) {
  const page = await browser.newPage({ viewport: { width: 1920, height: 1080 }, colorScheme: theme });
  await page.goto(`${base}?film=record&lang=${lang}`);
  await page.waitForFunction(() => window.fflFilm);
  const duration = await page.evaluate(() => window.fflFilm.duration);
  const frames = Math.round(duration * fps);
  const output = join(outDir, `ffl-explainer-${lang}.mp4`);
  const ffmpeg = spawn(
    "ffmpeg",
    ["-y", "-loglevel", "error", "-f", "image2pipe", "-framerate", String(fps), "-c:v", "png", "-i", "-",
     "-c:v", "libx264", "-pix_fmt", "yuv420p", "-crf", "18", "-preset", "slow", "-movflags", "+faststart", output],
    { stdio: ["pipe", "inherit", "inherit"] },
  );
  const done = new Promise((resolveExit, reject) =>
    ffmpeg.on("exit", (code) => (code === 0 ? resolveExit() : reject(new Error(`ffmpeg exited with ${code}`)))),
  );
  for (let frame = 0; frame < frames; frame++) {
    await page.evaluate((time) => window.fflFilm.seek(time), frame / fps);
    const png = await page.screenshot({ type: "png" });
    if (!ffmpeg.stdin.write(png)) await new Promise((drain) => ffmpeg.stdin.once("drain", drain));
    if (frame % fps === 0) process.stdout.write(`\r${lang}: ${Math.round((frame / frames) * 100)}%`);
  }
  ffmpeg.stdin.end();
  await done;
  console.log(`\r${lang}: ${output}`);
  await page.close();
}
await browser.close();
server.close();
