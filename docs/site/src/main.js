import i18next from "i18next";
import en from "./locales/en.json" with { type: "json" };
import zh_hans from "./locales/zh_hans.json" with { type: "json" };
import zh_hant from "./locales/zh_hant.json" with { type: "json" };

const resources = { en, zh_hans, zh_hant };
const htmlLanguages = { en: "en", zh_hans: "zh-Hans", zh_hant: "zh-Hant" };
const storageKey = "ffl-site-language";
const selector = document.querySelector("#language");
const text = (id, value) => {
  document.getElementById(id).textContent = value;
};
const t = (key) => i18next.t(key);
let workflow = "human";
let route = "internet";
let os = "unix";
let copyTimer;

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

const initialLanguage =
  normalizeLanguage(new URL(location.href).searchParams.get("lang")) ||
  savedLanguage() ||
  navigator.languages.map(normalizeLanguage).find(Boolean) ||
  "en";

await i18next.init({
  lng: initialLanguage,
  fallbackLng: "en",
  supportedLngs: Object.keys(resources),
  load: "currentOnly",
  resources: Object.fromEntries(
    Object.entries(resources).map(([language, translation]) => [
      language,
      { translation },
    ]),
  ),
  interpolation: { escapeValue: false }, // Translations are assigned with textContent, never HTML.
});

const workflows = {
  human: {
    title: "human-handoff.sh",
    command: "ffl ./photos --e2ee",
    receive: "https://<your-share-link>",
  },
  agent: {
    title: "agent-handoff.sh",
    command: "ffl ./artifacts --e2ee --json handoff.json --hook events.jsonl",
    receive: "ffl download <URL> --resume",
  },
  lan: {
    title: "local-model-handoff.sh",
    command: "ffl ./checkpoint --preferred-tunnel default:lan --e2ee",
    receive: "ffl download http://<LAN-IP>:<port>/<id> --resume",
  },
};

function markActive(attribute, value) {
  document.querySelectorAll(`[data-${attribute}]`).forEach((button) => {
    const active = button.dataset[attribute] === value;
    button.classList.toggle("active", active);
    button.setAttribute("aria-pressed", String(active));
  });
}

function renderWorkflow() {
  const example = workflows[workflow];
  text("terminal-title", example.title);
  text("workflow-command", example.command);
  text("workflow-receive", example.receive);
  text("workflow-comment", t(`${workflow}Comment`));
  text("workflow-receive-label", t(`${workflow}ReceiveLabel`));
  text("workflow-note", t(`${workflow}Note`));
  markActive("workflow", workflow);
}

function renderRoute() {
  const local = route === "local";
  text("route-note", t(local ? "routeLocalNote" : "routeInternetNote"));
  text("route-protocol", local ? "LAN / HTTP" : "P2P");
  text("route-fallback", t(local ? "routeLocalFallback" : "routeFallback"));
  text("privacy-note", t(local ? "privacyLocal" : "privacyInternet"));
  text(
    "route-command",
    local
      ? "ffl ./artifacts --preferred-tunnel default:lan --e2ee"
      : "ffl ./artifacts --e2ee",
  );
  markActive("route", route);
}

const installations = {
  unix: {
    shell: "BASH",
    command: "curl -fsSL https://fastfilelink.com/install.sh | bash",
    note: "installUnixNote",
  },
  windows: {
    shell: "POWERSHELL",
    command: "iwr -useb https://fastfilelink.com/install.ps1 | iex",
    note: "installWindowsNote",
  },
  ape: {
    shell: "BASH",
    command:
      "curl -fL https://github.com/nuwainfo/ffl/releases/latest/download/ffl.com -o ffl.com\nchmod +x ffl.com",
    note: "installApeNote",
  },
};

function renderInstall() {
  const install = installations[os];
  text("install-command", install.command);
  text("install-shell", install.shell);
  text("install-note", t(install.note));
  markActive("os", os);
}

function renderLanguage() {
  document.documentElement.lang = htmlLanguages[i18next.language];
  document.querySelectorAll("[data-i18n]").forEach((element) => {
    element.textContent = t(element.dataset.i18n);
  });
  document.querySelectorAll("[data-i18n-aria]").forEach((element) => {
    element.setAttribute("aria-label", t(element.dataset.i18nAria));
  });
  document.title = t("pageTitle");
  document.querySelector('meta[name="description"]').content =
    t("pageDescription");
  document.querySelector('meta[property="og:title"]').content = t("pageTitle");
  document.querySelector('meta[property="og:description"]').content =
    t("socialDescription");
  selector.value = i18next.language;
  text("copy-status", "");
  renderWorkflow();
  renderRoute();
  renderInstall();
}

selector.addEventListener("change", async () => {
  await i18next.changeLanguage(selector.value);
  try {
    localStorage.setItem(storageKey, i18next.language);
  } catch {
    /* Still works when storage is disabled. */
  }
  const url = new URL(location.href);
  url.searchParams.set("lang", i18next.language);
  history.replaceState(null, "", url);
  renderLanguage();
});

document.querySelectorAll("[data-workflow]").forEach((button) =>
  button.addEventListener("click", () => {
    workflow = button.dataset.workflow;
    renderWorkflow();
  }),
);
document.querySelectorAll("[data-route]").forEach((button) =>
  button.addEventListener("click", () => {
    route = button.dataset.route;
    renderRoute();
  }),
);
document.querySelectorAll("[data-os]").forEach((button) =>
  button.addEventListener("click", () => {
    os = button.dataset.os;
    renderInstall();
  }),
);
document.querySelectorAll("[data-copy]").forEach((button) =>
  button.addEventListener("click", async () => {
    const code = document.getElementById(button.dataset.copy);
    try {
      await navigator.clipboard.writeText(code.textContent);
      text("copy-status", t("copied"));
    } catch {
      const range = document.createRange();
      range.selectNodeContents(code);
      const selection = window.getSelection();
      selection.removeAllRanges();
      selection.addRange(range);
      text("copy-status", t("copyFailed"));
    }
    clearTimeout(copyTimer);
    copyTimer = setTimeout(() => text("copy-status", ""), 4500);
  }),
);

renderLanguage();
