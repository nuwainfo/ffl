import { test, expect } from "@playwright/test";
import en from "../src/locales/en.json" with { type: "json" };
import hans from "../src/locales/zh_hans.json" with { type: "json" };
import hant from "../src/locales/zh_hant.json" with { type: "json" };

const languages = {
  en: { resource: en, html: "en" },
  zh_hans: { resource: hans, html: "zh-Hans" },
  zh_hant: { resource: hant, html: "zh-Hant" },
};

test("all locales have complete, nonempty resources", () => {
  for (const { resource } of Object.values(languages)) {
    expect(Object.keys(resource).sort()).toEqual(Object.keys(en).sort());
    for (const value of Object.values(resource))
      expect(value.trim().length).toBeGreaterThan(0);
  }
});

for (const [language, { resource, html }] of Object.entries(languages)) {
  test(`${language}: production subpath, translated controls, responsive layout`, async ({
    page,
  }, testInfo) => {
    const errors = [];
    page.on("pageerror", (error) => errors.push(error.message));
    page.on("response", (response) => {
      if (response.status() >= 400)
        errors.push(`${response.status()} ${response.url()}`);
    });
    const requests = [];
    page.on("request", (request) => requests.push(request.url()));
    await page.goto(`?lang=${language}`);
    await expect(page.locator("html")).toHaveAttribute("lang", html);
    await expect(page).toHaveTitle(resource.pageTitle);
    await expect(page.locator('meta[name="description"]')).toHaveAttribute(
      "content",
      resource.pageDescription,
    );
    const translated = await page
      .locator("[data-i18n]")
      .evaluateAll((elements) =>
        elements.map((el) => ({ key: el.dataset.i18n, value: el.textContent })),
      );
    for (const { key, value } of translated)
      expect(value, key).toBe(resource[key]);
    const labelled = await page
      .locator("[data-i18n-aria]")
      .evaluateAll((elements) =>
        elements.map((el) => ({
          key: el.dataset.i18nAria,
          value: el.getAttribute("aria-label"),
        })),
      );
    for (const { key, value } of labelled)
      expect(value, key).toBe(resource[key]);
    for (const width of [1440, 768, 390, 320]) {
      await page.setViewportSize({ width, height: 1000 });
      expect(
        await page.evaluate(
          () => document.documentElement.scrollWidth <= innerWidth,
        ),
        `overflow at ${width}`,
      ).toBe(true);
      if (width === 1440 || width === 390)
        await page.screenshot({
          path: testInfo.outputPath(`${language}-${width}.png`),
          fullPage: true,
        });
      if (width === 1440 || width === 390)
        await page.screenshot({
          path: testInfo.outputPath(`${language}-${width}-hero.png`),
        });
    }
    await page.locator('[data-workflow="agent"]').click();
    await expect(page.locator("#workflow-command")).toContainText(
      "--json handoff.json --hook events.jsonl",
    );
    await expect(page.locator("#workflow-note")).toHaveText(resource.agentNote);
    await page.locator('[data-workflow="lan"]').click();
    await expect(page.locator("#workflow-command")).toContainText(
      "--preferred-tunnel default:lan",
    );
    await expect(page.locator("#workflow-note")).toHaveText(resource.lanNote);
    await page.locator('[data-route="local"]').click();
    await expect(page.locator("#privacy-note")).toHaveText(
      resource.privacyLocal,
    );
    await page.locator('[data-os="windows"]').click();
    await expect(page.locator("#install-command")).toHaveText(
      "iwr -useb https://fastfilelink.com/install.ps1 | iex",
    );
    await expect(page.locator("#install-note")).toHaveText(
      resource.installWindowsNote,
    );
    await page.locator('[data-os="ape"]').click();
    await expect(page.locator("#install-command")).toContainText(
      "chmod +x ffl.com",
    );
    await page.locator("summary").first().click();
    await expect(page.locator("details").first()).toHaveAttribute("open", "");
    expect(
      requests.every((url) => url.startsWith("http://127.0.0.1:4173/ffl/")),
    ).toBe(true);
    expect(errors).toEqual([]);
  });
}

test("language switching preserves chosen examples, query/hash, and saved preference", async ({
  page,
}) => {
  await page.goto("?lang=en#workflows");
  await page.locator('[data-workflow="agent"]').click();
  await page.locator('[data-route="local"]').click();
  await page.selectOption("#language", "zh_hant");
  await expect(page.locator("#workflow-note")).toHaveText(hant.agentNote);
  await expect(page.locator("#privacy-note")).toHaveText(hant.privacyLocal);
  await expect(page).toHaveURL(/lang=zh_hant#workflows$/);
  await page.goto("./");
  await expect(page.locator("html")).toHaveAttribute("lang", "zh-Hant");
  await page.goto("?lang=en");
  await expect(page.locator("html")).toHaveAttribute("lang", "en");
});

test("browser language, aliases, invalid query, and blocked storage", async ({
  browser,
}) => {
  const context = await browser.newContext({ locale: "zh-TW" });
  const page = await context.newPage();
  await page.addInitScript(() => {
    Storage.prototype.getItem = () => {
      throw new Error("disabled");
    };
    Storage.prototype.setItem = () => {
      throw new Error("disabled");
    };
  });
  await page.goto("http://127.0.0.1:4173/ffl/?lang=invalid");
  await expect(page.locator("html")).toHaveAttribute("lang", "zh-Hant");
  await page.goto("?lang=zh-CN");
  await expect(page.locator("html")).toHaveAttribute("lang", "zh-Hans");
  await page.selectOption("#language", "en");
  await expect(page.locator("html")).toHaveAttribute("lang", "en");
  await context.close();
});

test("copy writes the selected command and reports success", async ({
  page,
  context,
}) => {
  await context.grantPermissions(["clipboard-read", "clipboard-write"]);
  await page.goto("?lang=en");
  await page.locator('[data-workflow="agent"]').click();
  await page.locator('[data-copy="workflow-command"]').click();
  await expect(page.locator("#copy-status")).toHaveText(en.copied);
  expect(await page.evaluate(() => navigator.clipboard.readText())).toBe(
    await page.locator("#workflow-command").textContent(),
  );
  await page.locator('[data-os="windows"]').click();
  await page.locator('[data-copy="install-command"]').click();
  expect(await page.evaluate(() => navigator.clipboard.readText())).toBe(
    await page.locator("#install-command").textContent(),
  );
});

test("clipboard denial leaves selected text and useful localized feedback", async ({
  page,
}) => {
  await page.addInitScript(() =>
    Object.defineProperty(navigator, "clipboard", {
      value: {
        writeText: async () => {
          throw new Error("denied");
        },
      },
    }),
  );
  await page.goto("?lang=zh_hans");
  await page.locator('[data-copy="install-command"]').click();
  await expect(page.locator("#copy-status")).toHaveText(hans.copyFailed);
  expect(await page.evaluate(() => getSelection().toString())).toBe(
    await page.locator("#install-command").textContent(),
  );
});

test("keyboard navigation, reduced motion, and anchor destinations", async ({
  page,
}) => {
  await page.emulateMedia({ reducedMotion: "reduce" });
  await page.goto("?lang=en");
  await page.keyboard.press("Tab");
  await expect(page.locator(".skip")).toBeFocused();
  await page.keyboard.press("Enter");
  await expect(page).toHaveURL(/#main$/);
  const broken = await page
    .locator('a[href^="#"]')
    .evaluateAll((links) =>
      links
        .map((a) => a.getAttribute("href"))
        .filter(
          (href) => href !== "#" && !document.getElementById(href.slice(1)),
        ),
    );
  expect(broken).toEqual([]);
  await page.locator('[data-workflow="agent"]').focus();
  await page.keyboard.press("Enter");
  await expect(page.locator('[data-workflow="agent"]')).toHaveAttribute(
    "aria-pressed",
    "true",
  );
  expect(
    await page
      .locator(".connector span")
      .evaluate((el) => getComputedStyle(el).animationName),
  ).toBe("none");
});

test("English content and install links remain useful without JavaScript", async ({
  browser,
}) => {
  const context = await browser.newContext({ javaScriptEnabled: false });
  const page = await context.newPage();
  await page.goto("http://127.0.0.1:4173/ffl/");
  await expect(page.locator("h1")).toContainText("Transfer for");
  await expect(page.locator("#install-command")).toContainText(
    "https://fastfilelink.com/install.sh",
  );
  await expect(
    page.locator('a[href="https://github.com/nuwainfo/ffl/releases/latest"]'),
  ).toBeVisible();
  await context.close();
});
