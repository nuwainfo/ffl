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
    for (const value of Object.values(resource)) expect(value.trim().length).toBeGreaterThan(0);
  }
});

for (const [language, { resource, html }] of Object.entries(languages)) {
  test(`${language}: translated, no errors, no overflow`, async ({ page }) => {
    const errors = [];
    page.on("pageerror", (error) => errors.push(error.message));
    page.on("response", (response) => response.status() >= 400 && errors.push(`${response.status()} ${response.url()}`));
    const external = [];
    page.on("request", (request) => !request.url().startsWith("http://127.0.0.1") && external.push(request.url()));
    await page.emulateMedia({ reducedMotion: "reduce" });
    await page.goto(`?lang=${language}`);
    await expect(page.locator("html")).toHaveAttribute("lang", html);
    await expect(page).toHaveTitle(resource.pageTitle);
    // Elements with an id are driven by state (tabs, film); the rest must match the resource.
    const translated = await page
      .locator("[data-i18n]:not([id])")
      .evaluateAll((elements) => elements.map((el) => ({ key: el.dataset.i18n, value: el.textContent })));
    for (const { key, value } of translated) expect(value, key).toBe(resource[key]);
    const labelled = await page
      .locator("[data-i18n-aria]")
      .evaluateAll((elements) => elements.map((el) => ({ key: el.dataset.i18nAria, value: el.getAttribute("aria-label") })));
    for (const { key, value } of labelled) expect(value, key).toBe(resource[key]);
    await expect(page.locator("#film-svg #waybill")).toBeVisible();
    for (const width of [1440, 768, 390, 320]) {
      await page.setViewportSize({ width, height: 1000 });
      expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), `overflow at ${width}`).toBe(true);
    }
    expect(errors).toEqual([]);
    expect(external).toEqual([]);
  });
}

test("film plays, pauses, and jumps to chapters", async ({ page }) => {
  await page.emulateMedia({ reducedMotion: "reduce" });
  await page.goto("?lang=en");
  const toggle = page.locator("#film-toggle");
  await expect(toggle).toHaveText(en.filmPlay);
  await page.locator('[data-chapter="3"]').click();
  await expect(page.locator("#film-caption")).toHaveText(en.cap4);
  await expect(page.locator('[data-chapter="3"]')).toHaveAttribute("aria-current", "step");
  await expect(toggle).toHaveText(en.filmPause);
  await toggle.click();
  await expect(toggle).toHaveText(en.filmPlay);
  await page.locator("#language").selectOption("zh_hant");
  await expect(page.locator("#film-caption")).toHaveText(hant.cap4);
});

test("record mode exposes a seekable film", async ({ page }) => {
  await page.setViewportSize({ width: 1920, height: 1080 });
  await page.goto("?lang=en&film=record");
  await page.waitForFunction(() => window.fflFilm);
  expect(await page.evaluate(() => window.fflFilm.duration)).toBe(40);
  await page.evaluate(() => window.fflFilm.seek(35));
  await expect(page.locator("#film-caption")).toHaveText(en.cap6);
  await expect(page.locator(".header")).toBeHidden();
});

test("tabs, routes, install, and copy", async ({ page, context }) => {
  await context.grantPermissions(["clipboard-read", "clipboard-write"]);
  await page.emulateMedia({ reducedMotion: "reduce" });
  await page.goto("?lang=en");
  await page.locator('[data-workflow="agent"]').click();
  await expect(page.locator("#workflow-command")).toContainText("--json handoff.json --hook events.jsonl");
  await expect(page.locator("#workflow-receive-label")).toHaveText(en.slipTheyRun);
  await page.locator('[data-route="local"]').click();
  await expect(page.locator("#route-map")).toHaveAttribute("data-mode", "local");
  await expect(page.locator("#route-command")).toContainText("default:lan");
  await page.locator('[data-os="windows"]').click();
  await expect(page.locator("#install-command")).toContainText("install.ps1");
  await page.locator('[data-copy="install-command"]').click();
  await expect(page.locator("#copy-status")).toHaveText(en.copied);
  expect(await page.evaluate(() => navigator.clipboard.readText())).toContain("install.ps1");
});

test("theme switch cycles system, light, dark and is remembered", async ({ page }) => {
  await page.emulateMedia({ reducedMotion: "reduce", colorScheme: "light" });
  await page.goto("?lang=en");
  const html = page.locator("html");
  const toggle = page.locator("#theme");
  await expect(toggle).toHaveAttribute("aria-label", en.themeSystem);
  await toggle.click();
  await expect(html).toHaveAttribute("data-theme", "light");
  await toggle.click();
  await expect(html).toHaveAttribute("data-theme", "dark");
  await expect(toggle).toHaveAttribute("aria-label", en.themeDark);
  const paper = await page.evaluate(() => getComputedStyle(document.body).backgroundColor);
  expect(paper).toBe("rgb(14, 18, 38)");
  await page.reload();
  await expect(html).toHaveAttribute("data-theme", "dark");
  await toggle.click();
  await expect(html).not.toHaveAttribute("data-theme", /./);
});

test("each chapter opens with a stage title that fades; the caption below stays", async ({ page }) => {
  await page.setViewportSize({ width: 1920, height: 1080 });
  await page.goto("?lang=en&film=record");
  await page.waitForFunction(() => window.fflFilm);
  const at = async (time) => {
    await page.evaluate((time) => window.fflFilm.seek(time), time);
    return page.evaluate(() => ({
      title: Number(document.getElementById("film-title").style.opacity),
      titleText: document.getElementById("film-title").textContent,
      caption: getComputedStyle(document.getElementById("film-caption")).opacity,
    }));
  };
  expect((await at(6.5)).title).toBe(0);
  const open = await at(7.5);
  expect(open.title).toBe(1);
  expect(open.titleText).toBe(en.cap2);
  expect(open.caption).toBe("1");
  expect((await at(11)).title).toBe(0);
  expect((await at(11)).caption).toBe("1");
});

test("page colour picker recolours the field and accents", async ({ page }) => {
  await page.emulateMedia({ reducedMotion: "reduce", colorScheme: "light" });
  await page.goto("?lang=zh_hant");
  const field = () => page.evaluate(() => getComputedStyle(document.querySelector(".masthead")).backgroundColor);
  expect(await field()).toBe("rgb(42, 59, 212)");
  await page.locator(".accent-picker summary").click();
  await expect(page.locator('[data-accent-choice="green"]')).toHaveAttribute("aria-label", hant.accent_green);
  await page.locator('[data-accent-choice="green"]').click();
  await expect(page.locator("html")).toHaveAttribute("data-accent", "green");
  expect(await field()).toBe("rgb(18, 106, 80)");
  await expect(page.locator(".accent-picker")).not.toHaveAttribute("open", "");
  await page.reload();
  expect(await field()).toBe("rgb(18, 106, 80)");
});
