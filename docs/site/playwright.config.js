import { defineConfig } from "@playwright/test";

const sitePort = Number(process.env.FFL_SITE_PORT || 4174);
const baseURL = `http://127.0.0.1:${sitePort}/ffl/`;

export default defineConfig({
  testDir: "./tests",
  fullyParallel: true,
  workers: 2,
  use: {
    baseURL,
    browserName: "chromium",
    channel: process.env.FFL_SITE_BROWSER || undefined,
    viewport: { width: 1440, height: 1000 },
    trace: "retain-on-failure",
  },
  webServer: {
    command: `npm run build && npm run preview -- --port ${sitePort} --strictPort --base=/ffl/`,
    url: baseURL,
    reuseExistingServer: false,
  },
});
