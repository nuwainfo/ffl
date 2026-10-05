import i18next from "i18next";
import { createFilm, chapters, duration } from "./film.js";
import en from "./locales/en.json" with { type: "json" };
import zh_hans from "./locales/zh_hans.json" with { type: "json" };
import zh_hant from "./locales/zh_hant.json" with { type: "json" };

const resources = { en, zh_hans, zh_hant };
const htmlLanguages = { en: "en", zh_hans: "zh-Hans", zh_hant: "zh-Hant" };
const storageKey = "ffl-site-language";
const params = new URL(location.href).searchParams;
const recording = params.get("film") === "record";
const reducedMotion = matchMedia("(prefers-reduced-motion: reduce)");
const $ = (id) => document.getElementById(id);
const text = (id, value) => {
  $(id).textContent = value;
};
const t = (key) => i18next.t(key);

function normalizeLanguage(value) {
  const language = String(value || "")
    .replaceAll("_", "-")
    .toLowerCase();
  if (language.startsWith("zh")) {
    return /hant|tw|hk|mo/.test(language) ? "zh_hant" : "zh_hans";
  }
  if (language === "en" || language.startsWith("en-")) return "en";
  return undefined;
}

function savedLanguage() {
  try {
    return normalizeLanguage(localStorage.getItem(storageKey));
  } catch {
    return undefined;
  }
}

await i18next.init({
  lng:
    normalizeLanguage(params.get("lang")) ||
    savedLanguage() ||
    navigator.languages.map(normalizeLanguage).find(Boolean) ||
    "en",
  fallbackLng: "en",
  supportedLngs: Object.keys(resources),
  load: "currentOnly",
  resources: Object.fromEntries(
    Object.entries(resources).map(([language, translation]) => [language, { translation }]),
  ),
  interpolation: { escapeValue: false }, // Assigned with textContent, never HTML.
});

// --- Film ---------------------------------------------------------------

const film = {
  timeline: null,
  chapter: -1,
  autoplayed: false,
};
const chapterButtons = [...document.querySelectorAll("[data-chapter]")];
// GSAP's isActive() is false until the first rendered frame, so track running ourselves.
const running = (tl) => Boolean(tl && !tl.paused() && tl.time() < duration);

function chapterAt(time) {
  let index = 0;
  chapters.forEach((chapter, i) => {
    if (time >= chapter.start) index = i;
  });
  return index;
}

function renderFilmTime(time) {
  const index = chapterAt(time);
  chapterButtons.forEach((button, i) => {
    const start = chapters[i].start;
    const end = chapters[i + 1]?.start ?? duration;
    const progress = Math.min(1, Math.max(0, (time - start) / (end - start)));
    button.style.setProperty("--progress", progress);
    if (i === index) button.setAttribute("aria-current", "step");
    else button.removeAttribute("aria-current");
  });
  if (index !== film.chapter) {
    film.chapter = index;
    text("film-caption", t(chapters[index].caption));
    text("film-title", t(chapters[index].caption));
  }
  // The same line opens each chapter as a title on the stage, then fades away.
  // It follows the film's clock, so scrubbing and MP4 export show it too.
  const local = time - chapters[index].start;
  const enter = Math.min(1, Math.max(0, (local - 0.15) / 0.45));
  const leave = Math.min(1, Math.max(0, (3.4 - local) / 0.5));
  const title = $("film-title");
  title.style.opacity = Math.min(enter, leave).toFixed(3);
  title.style.transform = `translate(-50%, ${((enter - 1) * 16).toFixed(2)}px)`;
}

function renderFilmState() {
  const tl = film.timeline;
  renderFilmTime(tl.time());
  const playing = running(tl);
  const ended = tl.time() >= duration;
  document.querySelector(".film").classList.toggle("is-playing", playing);
  text("film-toggle-text", t(playing ? "filmPause" : ended ? "filmReplay" : "filmPlay"));
}

function buildFilm() {
  const time = film.timeline?.time() ?? 0;
  const wasPlaying = running(film.timeline);
  film.timeline?.kill();
  film.timeline = createFilm($("film-svg"), t, { onUpdate: renderFilmTime });
  film.timeline.eventCallback("onComplete", renderFilmState);
  film.chapter = -1;
  film.timeline.seek(time, false);
  renderFilmTime(time);
  if (wasPlaying) film.timeline.play();
  renderFilmState();
}

function play(from) {
  const tl = film.timeline;
  if (from !== undefined) tl.seek(from, false);
  else if (tl.time() >= duration) tl.seek(0, false);
  tl.play();
  renderFilmState();
}

$("film-toggle").addEventListener("click", () => {
  film.autoplayed = true;
  if (running(film.timeline)) {
    film.timeline.pause();
    renderFilmState();
  } else play();
});
chapterButtons.forEach((button, i) =>
  button.addEventListener("click", () => {
    film.autoplayed = true;
    play(chapters[i].start);
  }),
);

// --- Interactive examples -----------------------------------------------

const workflows = {
  human: { command: "ffl ./photos --e2ee", receive: "https://<your-share-link>", label: "slipTheyOpen" },
  agent: {
    command: "ffl ./artifacts --e2ee --json handoff.json --hook events.jsonl",
    receive: 'ffl download "$LINK" --resume',
    label: "slipTheyRun",
  },
  lan: {
    command: "ffl ./checkpoint --preferred-tunnel default:lan --e2ee",
    receive: "ffl download http://<LAN-IP>:<port>/<id> --resume",
    label: "slipTheyRun",
  },
};
const installations = {
  unix: { command: "curl -fsSL https://fastfilelink.com/install.sh | bash", note: "installUnixNote", run: "ffl" },
  windows: { command: "iwr -useb https://fastfilelink.com/install.ps1 | iex", note: "installWindowsNote", run: "ffl" },
  ape: {
    command: "curl -fL https://fastfilelink.com/ffl.com -o ffl.com && chmod +x ffl.com",
    note: "installApeNote",
    run: "./ffl.com",
  },
};
const state = { workflow: "human", route: "internet", os: "unix" };

function markActive(attribute, value) {
  document.querySelectorAll(`[data-${attribute}]`).forEach((button) => {
    button.setAttribute("aria-pressed", String(button.dataset[attribute] === value));
  });
}

function renderWorkflow() {
  const example = workflows[state.workflow];
  text("workflow-command", example.command);
  text("workflow-receive", example.receive);
  text("workflow-receive-label", t(example.label));
  text("workflow-note", t(`${state.workflow}Note`));
  markActive("workflow", state.workflow);
}

function renderRoute() {
  const local = state.route === "local";
  $("route-map").dataset.mode = state.route;
  text("route-note", t(local ? "routeLocalNote" : "routeInternetNote"));
  text("privacy-note", t(local ? "privacyLocal" : "privacyInternet"));
  text("route-tag", t(local ? "routeLan" : "routeDirect"));
  text("route-command", local ? "ffl ./artifacts --preferred-tunnel default:lan --e2ee" : "ffl ./artifacts --e2ee");
  markActive("route", state.route);
}

function renderInstall() {
  const install = installations[state.os];
  text("install-command", install.command);
  text("install-note", t(install.note));
  text("install-share", `${install.run} ./photos`);
  markActive("os", state.os);
}

for (const key of ["workflow", "route", "os"]) {
  document.querySelectorAll(`[data-${key}]`).forEach((button) =>
    button.addEventListener("click", () => {
      state[key] = button.dataset[key];
      ({ workflow: renderWorkflow, route: renderRoute, os: renderInstall })[key]();
    }),
  );
}

let copyTimer;
document.querySelectorAll("[data-copy]").forEach((button) =>
  button.addEventListener("click", async () => {
    const code = $(button.dataset.copy);
    try {
      await navigator.clipboard.writeText(code.textContent);
      text("copy-status", t("copied"));
      button.dataset.done = "";
    } catch {
      const range = document.createRange();
      range.selectNodeContents(code);
      getSelection().removeAllRanges();
      getSelection().addRange(range);
      text("copy-status", t("copyFailed"));
    }
    clearTimeout(copyTimer);
    copyTimer = setTimeout(() => {
      text("copy-status", "");
      delete button.dataset.done;
    }, 2400);
  }),
);

// --- Theme --------------------------------------------------------------

const themeKey = "ffl-site-theme";
const themes = ["system", "light", "dark"];
let theme = document.documentElement.dataset.theme || "system";

function renderTheme() {
  if (theme === "system") delete document.documentElement.dataset.theme;
  else document.documentElement.dataset.theme = theme;
  const button = $("theme");
  button.dataset.mode = theme;
  const label = t({ system: "themeSystem", light: "themeLight", dark: "themeDark" }[theme]);
  button.setAttribute("aria-label", label);
  button.title = label;
}

$("theme").addEventListener("click", () => {
  theme = themes[(themes.indexOf(theme) + 1) % themes.length];
  try {
    if (theme === "system") localStorage.removeItem(themeKey);
    else localStorage.setItem(themeKey, theme);
  } catch {
    /* Works without storage. */
  }
  renderTheme();
  renderAccent();
});

// --- Page colour ----------------------------------------------------------

const accentKey = "ffl-site-accent";
let accent = document.documentElement.dataset.accent || "blue";

function renderAccent() {
  if (accent === "blue") delete document.documentElement.dataset.accent;
  else document.documentElement.dataset.accent = accent;
  document.querySelectorAll("[data-accent-choice]").forEach((button) => {
    const label = t(`accent_${button.dataset.accentChoice}`);
    button.setAttribute("aria-pressed", String(button.dataset.accentChoice === accent));
    button.setAttribute("aria-label", label);
    button.title = label;
  });
  const field = getComputedStyle(document.documentElement).getPropertyValue("--field").trim();
  document.querySelectorAll('meta[name="theme-color"]').forEach((tag) => (tag.content = field));
}

document.querySelectorAll("[data-accent-choice]").forEach((button) =>
  button.addEventListener("click", () => {
    accent = button.dataset.accentChoice;
    try {
      if (accent === "blue") localStorage.removeItem(accentKey);
      else localStorage.setItem(accentKey, accent);
    } catch {
      /* Works without storage. */
    }
    renderAccent();
    button.closest("details").open = false;
  }),
);

// --- Language -----------------------------------------------------------

const selector = $("language");

function renderLanguage() {
  document.documentElement.lang = htmlLanguages[i18next.language];
  document.querySelectorAll("[data-i18n]").forEach((element) => {
    element.textContent = t(element.dataset.i18n);
  });
  document.querySelectorAll("[data-i18n-aria]").forEach((element) => {
    element.setAttribute("aria-label", t(element.dataset.i18nAria));
  });
  document.title = t("pageTitle");
  document.querySelector('meta[name="description"]').content = t("pageDescription");
  document.querySelector('meta[property="og:title"]').content = t("pageTitle");
  document.querySelector('meta[property="og:description"]').content = t("socialDescription");
  selector.value = i18next.language;
  text("copy-status", "");
  renderWorkflow();
  renderRoute();
  renderInstall();
  renderTheme();
  renderAccent();
  buildFilm();
}

selector.addEventListener("change", async () => {
  await i18next.changeLanguage(selector.value);
  try {
    localStorage.setItem(storageKey, i18next.language);
  } catch {
    /* Works without storage. */
  }
  const url = new URL(location.href);
  url.searchParams.set("lang", i18next.language);
  history.replaceState(null, "", url);
  renderLanguage();
});

await document.fonts.ready;
renderLanguage();

if (recording) {
  // Frame-accurate export: scripts/record-film.mjs seeks and screenshots.
  document.documentElement.classList.add("film-record");
  window.fflFilm = {
    duration,
    seek(time) {
      film.timeline.pause().seek(time, false);
      renderFilmTime(time);
    },
  };
} else if (reducedMotion.matches) {
  // Show a finished frame instead of moving on its own.
  film.timeline.seek(36.9, false);
  renderFilmTime(36.9);
  renderFilmState();
} else {
  new IntersectionObserver(
    (entries, observer) => {
      if (entries.some((entry) => entry.isIntersecting) && !film.autoplayed) {
        film.autoplayed = true;
        observer.disconnect();
        play(0);
      }
    },
    { threshold: 0.45 },
  ).observe($("film-svg"));
}
