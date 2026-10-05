// The explainer film: one paused GSAP timeline over an inline SVG stage.
// Everything is driven by timeline time, so the same film plays on the page,
// scrubs by chapter, and renders frame by frame for MP4 export.
import { gsap } from "gsap";
import { MotionPathPlugin } from "gsap/MotionPathPlugin";

gsap.registerPlugin(MotionPathPlugin);

const NS = "http://www.w3.org/2000/svg";
const LINK = "4567.81.fastfilelink.com/abcd1234";

export const chapters = [
  { key: "ch1", caption: "cap1", start: 0 },
  { key: "ch2", caption: "cap2", start: 6.5 },
  { key: "ch3", caption: "cap3", start: 13 },
  { key: "ch4", caption: "cap4", start: 19.5 },
  { key: "ch5", caption: "cap5", start: 26.5 },
  { key: "ch6", caption: "cap6", start: 33.5 },
];
export const duration = 40;

const escape = (value) =>
  String(value).replace(
    /[&<>"]/g,
    (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[c],
  );

// A deterministic barcode drawn from the link, so the waybill reads as real.
function barcode(x, y, width, height) {
  let bars = "";
  let cursor = x;
  for (let i = 0; cursor < x + width; i++) {
    const code = LINK.charCodeAt(i % LINK.length);
    const bar = 2 + (code % 3) * 2;
    const gap = 2 + ((code >> 2) % 3) * 2;
    if (cursor + bar > x + width) break;
    bars += `<rect x="${cursor}" y="${y}" width="${bar}" height="${height}"/>`;
    cursor += bar + gap;
  }
  return bars;
}

function markup(t) {
  const s = (key) => escape(t(key));
  const field = (id, y, label, value) => `
    <g id="${id}">
      <text class="f-field" x="590" y="${y}">${s(label)}</text>
      <text class="f-value" x="590" y="${y + 32}">${value}</text>
      <line class="f-hair" x1="590" x2="1010" y1="${y + 52}" y2="${y + 52}"/>
    </g>`;
  return `
  <defs>
    <pattern id="f-hatch" width="14" height="14" patternUnits="userSpaceOnUse" patternTransform="rotate(45)">
      <rect width="14" height="14" class="f-wall-bg"/><rect width="6" height="14" class="f-wall-stripe"/>
    </pattern>
    <pattern id="f-dots" width="32" height="32" patternUnits="userSpaceOnUse"><circle cx="4" cy="4" r="2.2" class="f-floor-dot"/></pattern>
  </defs>
  <rect class="f-floor" y="-40" width="1600" height="900"/>
  <rect y="-40" width="1600" height="900" fill="url(#f-dots)"/>

  <!-- Scene 1: the detour -->
  <g id="detour">
    <path id="detour-path" class="f-detour" d="M480 360 C 560 220, 610 172, 690 172 L 910 172 C 990 172, 1040 180, 1100 205"/>
    <g id="bucket">
      <path class="f-box" d="M690 92 v86 a110 26 0 0 0 220 0 v-86"/>
      <ellipse class="f-box" cx="800" cy="92" rx="110" ry="26"/>
      <text class="f-small f-center" x="800" y="140">${s("fBucket")}</text>
    </g>
    <g class="f-step" id="step-upload"><rect x="500" y="218" width="120" height="38" rx="19"/><text x="560" y="244">${s("fUpload")}</text></g>
    <g class="f-step" id="step-wait"><rect x="740" y="218" width="120" height="38" rx="19"/><text x="800" y="244">${s("fWait")}</text></g>
    <g class="f-step" id="step-share"><rect x="740" y="268" width="120" height="38" rx="19"/><text x="800" y="294">${s("fShare")}</text></g>
    <g class="f-step" id="step-download"><rect x="960" y="218" width="140" height="38" rx="19"/><text x="1030" y="244">${s("fDownload")}</text></g>
    <g class="f-step" id="step-cleanup"><rect x="730" y="318" width="140" height="38" rx="19"/><text x="800" y="344">${s("fCleanup")}</text></g>
    <rect id="detour-parcel" class="f-parcel" x="-11" y="-11" width="22" height="22" rx="3"/>
    <line id="detour-strike" class="f-strike" x1="640" y1="60" x2="960" y2="380"/>
  </g>

  <!-- The sender -->
  <g id="sender">
    <rect class="f-box" x="80" y="280" width="400" height="300" rx="16"/>
    <text class="f-field" x="104" y="316">${s("fSender")}</text>
    <rect class="f-term" x="100" y="332" width="360" height="104" rx="8"/>
    <text id="sender-cmd" class="f-term-text" x="120" y="392"></text>
    <rect id="sender-caret" class="f-caret" x="120" y="372" width="11" height="26"/>
    <path class="f-folder" d="M106 474 h30 l8 10 h44 v62 h-82 z"/>
    <text class="f-title-s" x="206" y="508">checkpoint/</text>
    <text class="f-small" x="206" y="538">14.2 GB</text>
  </g>

  <!-- Scene 2: the waybill -->
  <g id="waybill">
    <rect class="f-label" x="560" y="270" width="480" height="430" rx="10"/>
    <text class="f-wordmark" x="590" y="334">ffl</text>
    <g class="f-barcode">${barcode(760, 298, 250, 44)}</g>
    <line class="f-perf" x1="560" x2="1040" y1="368" y2="368"/>
    ${field("row-link", 400, "fLink", LINK)}
    ${field("row-contents", 474, "fContents", "checkpoint/   14.2 GB")}
    ${field("row-route", 548, "fRoute", s("fRouteVal"))}
    ${field("row-e2ee", 622, "fEncryption", s("fEncryptionVal"))}
    <g id="stamp" class="f-stamp">
      <rect x="770" y="560" width="260" height="96" rx="8"/>
      <rect x="780" y="570" width="240" height="76" rx="4"/>
      <text x="900" y="624">${s("fDelivered")}</text>
    </g>
  </g>

  <!-- Routes -->
  <path id="line-browser" class="f-route" d="M480 380 C 700 380, 860 200, 1100 200"/>
  <text id="line-browser-label" class="f-route-label" x="760" y="290">WebRTC</text>
  <path id="line-worker" class="f-route" d="M480 500 C 700 500, 880 660, 1100 660"/>
  <text id="line-worker-label" class="f-route-label" x="700" y="560">TCP/QUIC</text>
  <g id="flow-browser">${'<rect class="f-parcel" x="-7" y="-7" width="14" height="14" rx="2"/>'.repeat(4)}</g>
  <g id="flow-worker">${'<rect class="f-parcel" x="-7" y="-7" width="14" height="14" rx="2"/>'.repeat(4)}</g>

  <!-- Recipient: a person with a browser -->
  <g id="browser">
    <rect class="f-box" x="1100" y="70" width="420" height="280" rx="14"/>
    <line class="f-hair" x1="1100" x2="1520" y1="118" y2="118"/>
    <circle class="f-dot" cx="1126" cy="94" r="6"/><circle class="f-dot" cx="1146" cy="94" r="6"/><circle class="f-dot" cx="1166" cy="94" r="6"/>
    <rect class="f-address" x="1190" y="80" width="310" height="28" rx="14"/>
    <text id="browser-url" class="f-tiny" x="1204" y="99"></text>
    <g id="browser-page">
      <path class="f-file" d="M1130 150 h40 l14 14 v56 h-54 z"/>
      <text class="f-title-s" x="1200" y="180">${s("fBrowserTitle")}</text>
      <text class="f-small" x="1200" y="210">${s("fBrowserSub")}</text>
      <rect class="f-track" x="1130" y="248" width="360" height="12" rx="6"/>
      <rect id="browser-fill" class="f-fill" x="1130" y="248" width="360" height="12" rx="6"/>
      <g id="browser-check"><path class="f-check" d="M1132 302 l9 9 l18 -20"/><text class="f-small f-ink" x="1170" y="310">${s("fChecksum")}</text></g>
    </g>
  </g>
  <text id="browser-note" class="f-note" x="1100" y="390">${s("fNothing")}</text>

  <!-- Recipient: another agent -->
  <g id="worker">
    <rect class="f-term" x="1100" y="470" width="420" height="330" rx="14"/>
    <text class="f-term-dim" x="1124" y="506">${s("fWorker")}</text>
    <text id="worker-l1" class="f-term-text" x="1124" y="556"></text>
    <text id="worker-l2" class="f-term-text" x="1124" y="590"></text>
    <rect class="f-term-track" x="1124" y="622" width="372" height="10" rx="5"/>
    <rect id="worker-fill" class="f-fill" x="1124" y="622" width="372" height="10" rx="5"/>
    <text id="worker-l3" class="f-term-dim" x="1124" y="672">checkpoint/  14.2 GB</text>
    <text id="worker-l4" class="f-term-text" x="1124" y="740"></text>
  </g>
  <g id="handoff-json">
    <rect class="f-pill" x="0" y="0" width="300" height="44" rx="22"/>
    <text class="f-pill-text" x="22" y="29">{"link": "…/abcd1234"}</text>
  </g>
  <g id="events">
    <text class="f-field" x="80" y="640">events.jsonl</text>
    <text id="ev1" class="f-event" x="80" y="680">/share/link/create</text>
    <text id="ev2" class="f-event" x="80" y="716">/download/progress</text>
    <text id="ev3" class="f-event" x="80" y="752">/download/complete</text>
  </g>

  <!-- Scene 5: blocked path and relay -->
  <g id="wall"><rect x="770" y="510" width="40" height="190" rx="4" fill="url(#f-hatch)" class="f-wall"/></g>
  <text id="blocked" class="f-blocked" x="840" y="720">${s("fBlocked")}</text>
  <path id="relay-path" class="f-relay" d="M480 440 C 560 300, 600 112, 680 112 M 920 112 C 1000 112, 1040 400, 1100 600"/>
  <path id="relay-path-a" class="f-invisible" d="M480 440 C 560 300, 600 112, 680 112 L 920 112 C 1000 112, 1040 400, 1100 600"/>
  <g id="cipher">
    <rect class="f-pill" x="-70" y="-22" width="140" height="44" rx="10"/>
    <path class="f-lock" d="M-50 -2 h22 v18 h-22 z M-46 -2 v-6 a7 7 0 0 1 14 0 v6"/>
    <text class="f-pill-text" x="-18" y="7">9f3a7c01</text>
  </g>
  <g id="relay">
    <rect class="f-box" x="680" y="70" width="240" height="84" rx="12"/>
    <text class="f-title-s f-center" x="800" y="122">${s("fRelay")}</text>
  </g>
  <text id="cipher-note" class="f-note f-center" x="800" y="196">${s("fCipher")}</text>

  <!-- End card -->
  <g id="endcard">
    <text class="f-end-mark" x="120" y="470">ffl</text>
    <text class="f-end-line" x="124" y="560">${s("fEnd")}</text>
    <text class="f-end-cmd" x="124" y="640">curl -fsSL https://fastfilelink.com/install.sh | bash</text>
  </g>`;
}

export function createFilm(svg, t, { onUpdate } = {}) {
  svg.setAttribute("viewBox", "0 -40 1600 900");
  svg.innerHTML = markup(t);
  const $ = (id) => svg.querySelector(`#${id}`);
  const draw = (path) => {
    const length = path.getTotalLength();
    gsap.set(path, { strokeDasharray: length, strokeDashoffset: length });
    return length;
  };
  const typer = (tl, element, value, at, seconds) => {
    const state = { n: 0 };
    tl.to(
      state,
      {
        n: value.length,
        duration: seconds,
        ease: "none",
        onUpdate: () => {
          element.textContent = value.slice(0, Math.round(state.n));
        },
      },
      at,
    );
  };

  // Initial state. The timeline only uses .to(), so seeking backwards restores it.
  const hidden = [
    "bucket", "detour-path", "step-upload", "step-wait", "step-share",
    "step-download", "step-cleanup", "detour-parcel", "detour-strike",
    "waybill", "row-link", "row-contents", "row-route", "row-e2ee", "stamp",
    "line-browser", "line-browser-label", "line-worker", "line-worker-label",
    "flow-browser", "flow-worker", "browser", "browser-page", "browser-check",
    "browser-note", "worker", "handoff-json", "events", "ev1", "ev2", "ev3",
    "wall", "blocked", "relay", "relay-path", "cipher", "cipher-note",
    "endcard", "sender",
  ].map($);
  gsap.set(hidden, { autoAlpha: 0 });
  gsap.set(["#browser-fill", "#worker-fill"].map((q) => svg.querySelector(q)), {
    scaleX: 0,
    transformOrigin: "0 50%",
  });
  draw($("detour-path"));
  draw($("line-browser"));
  draw($("line-worker"));
  gsap.set($("stamp"), { scale: 2.4, rotation: -8, svgOrigin: "900 608" });
  gsap.set($("wall"), { y: -560 });
  // Parcels wait at the start of their route until their staggered run begins.
  gsap.set($("flow-browser").children, { x: 480, y: 380 });
  gsap.set($("flow-worker").children, { x: 480, y: 500 });
  gsap.set($("handoff-json"), { x: 110, y: 610 });
  gsap.set($("cipher"), { x: 480, y: 440 });
  gsap.set($("waybill"), { y: 40 });

  const tl = gsap.timeline({
    paused: true,
    defaults: { ease: "power3.out", duration: 0.6 },
    onUpdate: () => onUpdate?.(tl.time()),
  });
  tl.set({}, {}, duration);

  // 1. The detour: upload, wait, share, download, clean up.
  tl.to($("sender"), { autoAlpha: 1, duration: 0.5 }, 0.2);
  tl.to($("browser"), { autoAlpha: 1, duration: 0.5 }, 0.4);
  tl.to($("bucket"), { autoAlpha: 1 }, 0.8);
  tl.to($("detour-path"), { autoAlpha: 1, duration: 0.01 }, 1);
  tl.to($("detour-path"), { strokeDashoffset: 0, duration: 1.4, ease: "power1.inOut" }, 1);
  tl.to($("detour-parcel"), { autoAlpha: 1, duration: 0.2 }, 1.2);
  // The parcel crawls: quick up, stalls in the bucket, slowly down.
  const parcelPath = { path: $("detour-path"), align: $("detour-path"), alignOrigin: [0.5, 0.5] };
  tl.to($("detour-parcel"), { motionPath: { ...parcelPath, end: 0.42 }, duration: 0.9, ease: "power1.in" }, 1.2);
  tl.to($("detour-parcel"), { motionPath: { ...parcelPath, start: 0.42, end: 0.58 }, duration: 1.4, ease: "none" }, 2.1);
  tl.to($("detour-parcel"), { motionPath: { ...parcelPath, start: 0.58, end: 1 }, duration: 1, ease: "power1.in" }, 3.5);
  ["step-upload", "step-wait", "step-share", "step-download", "step-cleanup"].forEach((id, i) =>
    tl.to($(id), { autoAlpha: 1, duration: 0.3 }, 1.4 + i * 0.6),
  );
  tl.to($("detour-strike"), { autoAlpha: 1, duration: 0.15, ease: "none" }, 4.8);
  tl.to($("detour"), { autoAlpha: 0.12, duration: 0.6 }, 5.4);
  tl.to($("detour"), { autoAlpha: 0, duration: 0.4 }, 6.2);

  // 2. One command prints a waybill. The files stay put.
  typer(tl, $("sender-cmd"), "$ ffl ./checkpoint --e2ee", 6.7, 1.6);
  tl.to($("sender-caret"), { x: 286, duration: 1.6, ease: "none" }, 6.7);
  tl.to($("sender-caret"), { autoAlpha: 0, duration: 0.1 }, 8.4);
  tl.to($("waybill"), { autoAlpha: 1, y: 0, duration: 0.7 }, 8.5);
  ["row-link", "row-contents", "row-route", "row-e2ee"].forEach((id, i) =>
    tl.to($(id), { autoAlpha: 1, duration: 0.4 }, 9.1 + i * 0.45),
  );

  // 3. To a person: the link goes into a browser; bytes flow directly.
  tl.to($("waybill"), { scale: 0.42, x: -460, y: 340, svgOrigin: "560 270", duration: 0.8, ease: "power2.inOut" }, 13);
  typer(tl, $("browser-url"), LINK, 13.6, 0.8);
  tl.to($("browser-page"), { autoAlpha: 1 }, 14.4);
  tl.to($("line-browser"), { autoAlpha: 1, duration: 0.01 }, 14.6);
  tl.to($("line-browser"), { strokeDashoffset: 0, duration: 0.9, ease: "power2.inOut" }, 14.6);
  tl.to($("line-browser-label"), { autoAlpha: 1 }, 15.2);
  tl.to($("flow-browser"), { autoAlpha: 1, duration: 0.2 }, 15.3);
  const flow = (group, path, at, repeats) =>
    tl.to(
      group.children,
      {
        motionPath: { path, align: path, alignOrigin: [0.5, 0.5] },
        duration: 1.1,
        ease: "none",
        stagger: { each: 0.28, repeat: repeats },
      },
      at,
    );
  flow($("flow-browser"), $("line-browser"), 15.3, 2);
  tl.to($("browser-fill"), { scaleX: 1, duration: 3, ease: "power1.inOut" }, 15.3);
  tl.to($("browser-note"), { autoAlpha: 1 }, 16);
  tl.to($("flow-browser"), { autoAlpha: 0, duration: 0.3 }, 18.6);
  tl.to($("browser-check"), { autoAlpha: 1, duration: 0.4 }, 18.4);

  // 4. To an agent: the same link, a JSON handoff, and the job continues.
  tl.to($("waybill"), { autoAlpha: 0, duration: 0.4 }, 19.5);
  tl.to([$("browser"), $("browser-note"), $("line-browser"), $("line-browser-label")], { autoAlpha: 0.3 }, 19.6);
  tl.to($("worker"), { autoAlpha: 1 }, 19.8);
  tl.to($("handoff-json"), { autoAlpha: 1, duration: 0.3 }, 20);
  tl.to($("handoff-json"), { x: 1160, y: 410, duration: 1.1, ease: "power2.inOut" }, 20.4);
  tl.to($("handoff-json"), { autoAlpha: 0, duration: 0.3 }, 21.6);
  typer(tl, $("worker-l1"), "$ ffl download …/abcd1234", 21.5, 1.1);
  typer(tl, $("worker-l2"), "    --resume", 22.6, 0.4);
  tl.to($("line-worker"), { autoAlpha: 1, duration: 0.01 }, 23);
  tl.to($("line-worker"), { strokeDashoffset: 0, duration: 0.8, ease: "power2.inOut" }, 23);
  tl.to($("line-worker-label"), { autoAlpha: 1 }, 23.5);
  tl.to($("flow-worker"), { autoAlpha: 1, duration: 0.2 }, 23.4);
  flow($("flow-worker"), $("line-worker"), 23.4, 1);
  tl.to($("worker-fill"), { scaleX: 1, duration: 2, ease: "power1.inOut" }, 23.4);
  tl.to($("events"), { autoAlpha: 1, duration: 0.3 }, 23.2);
  ["ev1", "ev2", "ev3"].forEach((id, i) => tl.to($(id), { autoAlpha: 1, duration: 0.25 }, 23.3 + i * 1));
  tl.to($("flow-worker"), { autoAlpha: 0, duration: 0.3 }, 25.4);
  typer(tl, $("worker-l4"), "$ python train.py", 25.4, 0.6);

  // 5. Your route: the direct path is blocked, the relay carries ciphertext.
  tl.to([$("events"), $("browser"), $("browser-note"), $("line-browser"), $("line-browser-label")], { autoAlpha: 0, duration: 0.4 }, 26.5);
  tl.to($("wall"), { autoAlpha: 1, duration: 0.01 }, 26.8);
  tl.to($("wall"), { y: 0, duration: 0.5, ease: "bounce.out" }, 26.8);
  tl.to($("line-worker"), { attr: { class: "f-route f-broken" }, duration: 0.01 }, 27.3);
  tl.to($("line-worker-label"), { autoAlpha: 0, duration: 0.2 }, 27.3);
  tl.to($("blocked"), { autoAlpha: 1, duration: 0.3 }, 27.4);
  tl.to($("relay"), { autoAlpha: 1 }, 28);
  tl.to($("relay-path"), { autoAlpha: 1, duration: 0.4 }, 28.4);
  tl.to($("relay-path"), { strokeDashoffset: -120, duration: 5, ease: "none" }, 28.4);
  tl.to($("cipher"), { autoAlpha: 1, duration: 0.2 }, 29);
  tl.to(
    $("cipher"),
    {
      motionPath: { path: $("relay-path-a"), align: $("relay-path-a"), alignOrigin: [0.5, 0.5] },
      duration: 3.4,
      ease: "power1.inOut",
    },
    29,
  );
  tl.to($("cipher-note"), { autoAlpha: 1 }, 29.8);
  tl.to($("cipher"), { autoAlpha: 0, duration: 0.3 }, 32.4);

  // 6. Delivered: the stamp lands, then the end card.
  tl.to(
    [$("wall"), $("blocked"), $("relay"), $("relay-path"), $("cipher-note"), $("worker"), $("line-worker")],
    { autoAlpha: 0, duration: 0.4 },
    33.5,
  );
  tl.to($("waybill"), { autoAlpha: 1, scale: 1, x: 0, y: -60, duration: 0.6 }, 33.7);
  tl.to($("stamp"), { autoAlpha: 1, duration: 0.05 }, 34.5);
  tl.to($("stamp"), { scale: 1, duration: 0.28, ease: "power4.in" }, 34.5);
  tl.to($("waybill"), { x: 4, y: -56, duration: 0.06, yoyo: true, repeat: 1, ease: "none" }, 34.78);
  tl.to([$("waybill"), $("sender")], { autoAlpha: 0, duration: 0.5 }, 36.9);
  tl.to($("endcard"), { autoAlpha: 1, duration: 0.7 }, 37.3);

  return tl;
}
