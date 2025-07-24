# FastFileLink CLI

**FastFileLink CLI** is a fast, no-fuss command-line tool for sending files to anyone—instantly. No installation. No login required. No cloud uploads unless you want to.

It supports:
- 📡 Instant peer-to-peer (P2P) file sharing using WebRTC
- 🔁 Automatic fallback to secure tunnel relays (when NAT traversal fails)
- ☁️ Optional temporary upload to server (requires a licensed version)
- 🧱 Works on Windows, Linux, and macOS (x64/arm64)
- 🧰 Ideal for automation, scripting, headless systems, and CI pipelines

👉 Official site: [https://fastfilelink.com](https://fastfilelink.com)  
👉 Technical details: [Technical FAQ](https://fastfilelink.com/static/blog/technical_faqs.html)

---

## 🔧 Quick Examples

### 🔁 1. Peer-to-peer sharing (default, fully free)

```
ffl myfile.zip
```

→ Outputs a shareable link like:

```
https://4567.81.fastfilelink.com/abcd1234
```

- Recipient can download from any browser or CLI tools
- Transfer uses WebRTC if possible
- If P2P fails, auto-relays through our free unlimited tunnel

---

### ☁️ 2. Upload and share via server (requires Standard version or higher)

```
ffl myfile.zip --upload "1 day"
```

→ File is temporarily uploaded to our server and the download link is valid for 1 day.

📌 This feature requires login and a licensed version.  
See pricing & plans at: [https://fastfilelink.com](https://fastfilelink.com)

---

### 🔑 3. Login manually (optional, only needed for uploads)

```
ffl login
# or specify email
ffl login --email user@example.com
```

You’ll receive a one-time code via email.  
Once logged in, your device is authorized permanently unless removed.

---

## ✨ Features

- **📎 Zero-setup**  
  Just download the binary and run. No dependencies, no Python install required.

- **⚡ Instant file delivery**  
  Peer-to-peer transfers using WebRTC, with relay fallback. Fully encrypted, ephemeral, and fast.

- **🛡️ Secure by design**  
  No account needed for P2P. Files never touch our server unless explicitly uploaded.

- **🧰 CLI-first, automation-friendly**  
  Pipe files, build into CI/CD flows, cron jobs, or remote sessions.

- **🌐 Built-in tunnel support**  
  Uses our free unlimited relay tunnel when NAT traversal fails. You can also plug in your own Cloudflare Tunnel.

- **🪶 Lightweight binaries**  
  Portable standalone builds for Linux, Windows, and macOS. Cross-compiled with Cosmopolitan for wider compatibility.

---

## 🔓 Open Source (CLI Core Only)

This repository provides the **open-source FastFileLink CLI**, licensed under **AGPL v3**.

The following are **not open source** at this time:
- GUI version
- Upload server and APIs
- Tunnel coordination infrastructure

---

## 📦 Download Binaries

Visit the official site for the latest CLI builds for:

- Windows (x64)
- Linux (x64 / arm64)
- macOS (Intel + M1/M2)

👉 [https://fastfilelink.com/download](https://fastfilelink.com/download)

---

## 🧪 Coming Soon

- GUI integration for CLI workflow
- Server deployment guides
- Webhooks & advanced developer APIs

---

## 🤝 Commercial / Enterprise Use?

Need enterprise licensing, custom deployment, or CI automation support?  
Contact us at [support@fastfilelink.com](mailto:support@fastfilelink.com)

---
