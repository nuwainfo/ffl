import { defineConfig } from "@playwright/test";

export default defineConfig({
  testDir: "./tests",
  fullyParallel: true,
  workers: 2,
  use: {
    baseURL: "http://127.0.0.1:4173/ffl/",
    browserName: "chromium",
    channel: process.env.FFL_SITE_BROWSER || undefined,
    viewport: { width: 1440, height: 1000 },
    trace: "retain-on-failure",
  },
  webServer: {
    command:
      "npm run build && npm run preview -- --port 4173 --strictPort --base=/ffl/",
    url: "http://127.0.0.1:4173/ffl/",
    reuseExistingServer: false,
  },
});
