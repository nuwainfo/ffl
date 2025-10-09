# FastFileLink CLI

[![License](https://img.shields.io/github/license/nuwainfo/ffl?style=flat-square)](./LICENSE)
[![Release](https://img.shields.io/github/v/release/nuwainfo/ffl?style=flat-square)](https://github.com/nuwainfo/ffl/releases/latest)
[![Build](https://img.shields.io/github/actions/workflow/status/nuwainfo/ffl?style=flat-square)](https://github.com/nuwainfo/ffl/actions)

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

## 🚀 Using Tunnels

ffl supports various tunnels to help you transfer files efficiently through different network environments. By default, ffl comes with a built-in tunnel called default.

- **🌐 Supported Tunnels**
  
  We currently support the following tunnel types:
  - [Cloudflare](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/)
  - [Ngrok](https://ngrok.com/)
  - [Localtunnel](https://theboroer.github.io/localtunnel-www/)
  - [Loophole](https://loophole.cloud/)
  - [Dev-tunnel](https://learn.microsoft.com/zh-tw/azure/developer/dev-tunnels/overview)
  - [Bore](https://github.com/ekzhang/bore)

   If you want to use any of these tunnels, make sure the tunnel program is already installed on your system. Once installed, no additional configuration is needed — simply set your preferred tunnel once using:
  ```
  --preferred-tunnel <tunnel_name>
  ```
  After setting it, you won’t need to modify the configuration file or add --preferred-tunnel in future commands — it will be remembered until you change it again.

- **➕ Adding or Modifying Tunnels**

  If you want to add a new tunnel or modify an existing one, edit the configuration file located in your home directory:
  ```
  ~/.fastfilelink/tunnels.json
  ```
  A full example configuration file:
  ```json
  {
    "tunnels": {
        "cloudflare": {
            "name": "Cloudflare Tunnel",
            "binary": "cloudflared",
            "args": ["tunnel", "--url", "http://127.0.0.1:{port}"],
            "url_pattern": "https://[^\\s]+\\.trycloudflare\\.com",
            "timeout": 30,
            "enabled": true
        },
        "cloudflare-fixed": {
            "name": "Cloudflare Fixed Domain",
            "url": "https://my-tunnel.example.com",
            "enabled": false,
            "_comment": "Example of fixed URL tunnel, just specify the URL. Enable and set your own domain."
        },
        "ngrok": {
            "name": "ngrok",
            "binary": "ngrok",
            "args": ["http", "{port}", "--log", "stdout"],
            "url_pattern": "https://[^\\s]+\\.ngrok[^\\s]*",
            "timeout": 30,
            "enabled": true
        },
        "localtunnel": {
            "name": "LocalTunnel",
            "binary": "lt",
            "args": ["--port", "{port}"],
            "url_pattern": "https://[^\\s]+\\.loca\\.lt",
            "timeout": 30,
            "enabled": true
        },
        "loophole": {
            "name": "loophole",
            "binary": "loophole",
            "args": ["http", "{port}"],
            "url_pattern": "https://[^\\s]+\\.loophole\\.site",
            "timeout": 30,
            "enabled": true
        },
        "devtunnel": {
            "name": "Dev Tunnel",
            "binary": "devtunnel",
            "args": ["host", "-p", "{port}"],
            "url_pattern": "https://[^\\s]+\\.asse\\.devtunnels\\.ms",
            "timeout": 30,
            "enabled": true
        },
        "bore": {
            "name": "bore",
            "binary": "bore",
            "args": ["local", "{port}", "--to", "bore.pub"],
            "url_pattern": "bore\\.pub:\\d+",
            "timeout": 30,
            "enabled": true
        }
    },
    "settings": {
        "preferred_tunnel": "cloudflare",
        "fallback_order": ["cloudflare", "ngrok", "localtunnel", "loophole", "devtunnel", "bore", "default"]
    }
  }
  ```

  About Fixed Tunnels:
  
  A fixed tunnel always uses the same URL instead of generating a new one each time.
  If you own a custom domain or a permanent Cloudflare tunnel address, you can add it to the config (as in cloudflare-fixed above), set
  ```
  "enabled": true,
  ```
  and replace the URL with your own. Once enabled, ffl will always use that fixed address.
  Note: When using a fixed tunnel, you must also specify the listening port with
  ```
  --port PORT
  ```
  to ensure it works correctly.

  
- **⚠️ Performance Note**

  ffl’s default tunnel is maintained to be as fast, stable, and unrestricted as possible. However, during heavy usage by multiple users, you may still experience lag or slowdowns.
  
  If this happens, we recommend switching to Cloudflare tunnel for better performance — in fact, we suggest using Cloudflare from the start, especially in fixed mode, for the most stable and fastest experience.

---

## 🔓 Open Source (CLI Core Only)

This repository provides the **open-source FastFileLink CLI**, licensed under **Apache License 2.0**.

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
