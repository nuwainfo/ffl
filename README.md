# FastFileLink CLI (ffl)

**FastFileLink CLI (ffl)** is an [*Actually Portable*](https://justine.lol/ape.html) command-line tool that turns any file or folder into a secure HTTPS link, allowing two computers to simply and securely transfer files using real peer-to-peer (WebRTC) connections.

AFAIK, ffl is the only CLI file-transfer tool that does all of the following:

- 📡 **Instant P2P file sharing using WebRTC**
- 🔁 **Automatic fallback to secure relay tunnels** when NAT traversal fails — guarantees delivery
- 🧑‍💻 **Recipient doesn’t need to install anything** — they can download via browser, `curl`, etc. (P2P if using browser or `ffl` on both sides)
- 🔐 **End-to-end encryption (AES-256-GCM)** — relay/storage is zero-knowledge
- 📁 **Folder & multi-file support** — streaming, no need to zip/encrypt first, works even for TB-scale data
- ⏯️ **Resume interrupted transfers**
- 🧱 **Actually Portable Executable (APE)** + native builds for **Windows, Linux, macOS**
- 🧰 **Built-in & pluggable tunnels** (Cloudflare, ngrok, localtunnel, ... etc.) — can also go through a proxy like Tor
- ☁️ **Optional temporary upload to server** (licensed feature) when both sides can’t be online at the same time

👉 Official site: <https://fastfilelink.com>  
👉 Technical details: [*Technical FAQ*](https://fastfilelink.com/static/blog/technical_faqs.html)

---

## Installation

### Native installs

#### Linux / macOS

```bash
curl -fsSL https://raw.githubusercontent.com/nuwainfo/ffl/refs/heads/main/install.sh | bash
```

Install for current user only:

```bash
FFL_PREFIX=$HOME/.local curl -fsSL https://raw.githubusercontent.com/nuwainfo/ffl/refs/heads/main/install.sh | bash
```

#### Windows (PowerShell)

```powershell
iwr -useb https://raw.githubusercontent.com/nuwainfo/ffl/refs/heads/main/install.ps1 | iex
```

After installation, you should have `ffl` on your `$PATH`:

```bash
ffl --version
```

### Get the APE (Actually Portable Executable)

If you prefer a single-file binary that runs almost anywhere, use the APE build:

#### Linux / macOS

```bash
curl -fL https://github.com/nuwainfo/ffl/releases/latest/download/ffl.com -o ffl.com 
chmod +x ffl.com
```

#### Windows (PowerShell)

```powershell
curl "https://github.com/nuwainfo/ffl/releases/latest/download/ffl.com" -o "ffl.com"
```

---

### Build from source

If you prefer to build from source (requires **conda** and **cargo**):

```bash
conda create -n ffl python=3.12
conda activate ffl
pip install -r requirements.txt

# Linux
./BuildCLI.sh ffl

# Windows
.\BuildCLI.bat ffl
```

---

## Why APE and native executables both exist?

The **APE** ([Actually Portable Executable](https://justine.lol/ape.html)) build is cross-platform and runs on many OSes by emulating a POSIX environment (via [Cosmopolitan Libc](https://justine.lol/cosmopolitan/)). This is powerful but makes platform-specific optimizations harder.

So ffl also ships **native builds**:

- Windows native build includes `winloop`
- Linux/macOS builds use `uvloop`
- Native builds can be smaller (e.g. no ARM64 inside x86_64 binary)
- In rare cases where the APE build has issues, native builds are a good fallback

If you just want “runs everywhere with zero setup”, use **APE**.  
If you care about maximum performance and smaller size on a specific platform, use **native**.

## Quickstart

### 🔁 Share a file or folder (P2P first, tunnel as fallback)

```bash
ffl myfile.zip
# or
ffl /path/to/folder
```

You’ll get a shareable link like:

```text
https://4567.81.fastfilelink.com/abcd1234
```

- Recipient can download via browser or CLI, e.g.: ```curl -o file.zip https://4567.81.fastfilelink.com/abcd1234```
- Transfer prefers **WebRTC P2P** when possible  
- If P2P fails, it automatically falls back to HTTPS relay via a tunnel (third-party or our free unlimited tunnel)

> Note: CLI tools like `curl` / `wget` use HTTPS only. If you also want P2P on the receiving side using CLI, use `ffl` to download.

---

### 🔁 Receive using `ffl`

```bash
ffl https://4567.81.fastfilelink.com/abcd1234
```

- Tries **WebRTC P2P** first  
- If NAT traversal fails, automatically resumes via HTTPS relay  

---

## CLI Reference (short version)

For full help:

```bash
ffl --help
ffl download --help
```

The core options for sharing:

```text
ffl [options] [FILE_OR_FOLDER]

Options (most useful ones):

  --upload {3 hours,6 hours,12 hours,24 hours,72 hours}
      Upload to FastFileLink server and share via temporary storage
  --resume
      Resume a previously interrupted upload
  --pause PERCENTAGE
      Pause upload at specific percentage (1–99, requires --upload)
  --max-downloads N
      Auto-shutdown after N downloads (P2P mode). 0 = unlimited
  --timeout SECONDS
      Auto-shutdown after idle timeout (P2P mode). 0 = no timeout
  --port PORT
      Local HTTP server port (auto-detect by default)
  --auth-user USERNAME
  --auth-password PASSWORD
      HTTP Basic Auth for downloads
  --force-relay
      Force relayed P2P mode, disable direct WebRTC
  --e2ee
      Enable end-to-end encryption
  --alias ALIAS
      Use a custom alias as UID in the link
  --preferred-tunnel {cloudflare,default,...}
      Set preferred tunnel for future runs
  --json FILE
      Output link and settings to a JSON file
```

Download subcommand (when explicitly using `download`):

```bash
ffl download --help
```

## 1. End-to-end encryption & Authentication

Enable end-to-end encryption:

```bash
ffl myfile.bin --e2ee
```

Example output:

```text
🔐 End-to-end encryption enabled

Establishing tunnel connection...

Please share the link below with the person you'd like to share the file with.
https://53969.852.fastfilelink.com/MZoWzhPl

Please keep the application running so the recipient can download the file.
Press Ctrl+C to terminate the program when done.
```

In this mode, every chunk is encrypted with a unique IV, tag and AAD.  
Even though WebRTC already uses DTLS, if ffl falls back to HTTPS relay, the tunnel server **still cannot decrypt** the data, because:

- Key exchange happens between peers  
- Relay only sees encrypted chunks (zero-knowledge)

Add HTTP Basic Auth on top (with or without `--e2ee`):

```bash
ffl myfile.bin --auth-user tom --auth-password mypassword
```

This prevents anonymous downloads even if the link leaks.

---

## 2. Automation tips

ffl is designed for many downloaders; you can always stop sharing with `Ctrl+C`.  
But for automation / scripting, these flags help:

```bash
ffl myfile.bin --max-downloads 1
# Automatically terminate after one successful download
```

Generate JSON for scripts:

```bash
ffl myfile.bin --json ffl.json --max-downloads 1 &
jq -r .link ffl.json
```

This is useful in CI/CD, server-to-server workflows, and custom tooling.

## 3. 🚀 Using Tunnels

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
  ffl --preferred-tunnel cloudflare
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
  ffl myfile.bin --port 8080
  ```
  to ensure it works correctly.

  
- **⚠️ Performance Note**

  ffl’s default tunnel is maintained to be as fast, stable, and unrestricted as possible. However, during heavy usage by multiple users, you may still experience lag or slowdowns.
  
  If this happens, we recommend switching to Cloudflare tunnel for better performance — in fact, we suggest using Cloudflare from the start, especially in fixed mode, for the most stable and fastest experience.

## 4. Downloading with ffl (wget replacement)

ffl can also act like an HTTP download tool:

```bash
ffl https://zh.wikipedia.org/static/images/icons/wikipedia.png
# Saved as wikipedia.png
```

If the URL is a **FastFileLink** link, ffl:

- Uses WebRTC when possible  
- Supports resume via `--resume`:

  ```bash
  ffl https://53969.852.fastfilelink.com/MZoWzhPl -o myfile.bin

  # If interrupted:
  ffl https://53969.852.fastfilelink.com/MZoWzhPl -o myfile.bin --resume
  ```

---

## 5. ☁️ Upload and share via server (licensed feature)

If both sides cannot be online at the same time, you can upload once and share a server-hosted link.

```bash
ffl myfile.zip --upload "1 day"
```

- File is temporarily uploaded to our server  
- Download link is valid for the chosen duration (e.g. `"1 day"`)

This requires:

- A registered account  
- A licensed plan (Standard or higher)

See pricing: <https://fastfilelink.com/#pricing>

Login:

```bash
ffl login     # enter email and OTP
ffl status    # check account status
```

Example:

```text
Authentication Status:
   User: test@nuwainfo.com
   Email: test@nuwainfo.com
   Level: Free
   Serial: 0123456789
   Points: 0
   Registered: Yes
```

## How it works & Motivation

In short, `ffl` starts a small HTTP server on your machine, which also acts as a WebRTC signaling server.  
Then it exposes that local server through a tunnel so that the outside world can reach it.  
From there, the sender and receiver can:

- Talk directly via WebRTC P2P when possible, or  
- Fall back to a relay tunnel when direct connectivity is not available.

### Why build this?

Every time I needed to move files in and out of a container, it was painful:

- The container usually has almost nothing installed.
- It sits behind the host’s NAT and other layers of isolation.
- I don’t always have convenient shared volumes or SFTP handy.

The most practical trick I kept using (without extra infrastructure) was:

1. Install a tunnel tool inside the container (e.g. `bore`, `cloudflared`, etc.).
2. Run a simple HTTP file server like `python -m http.server`.
3. Use the tunnel URL from outside to pull the files out.

It’s not the only solution, and definitely not the “most elegant”, but it works extremely well in my environment.  
The reverse direction (sending files *into* the container) is similarly clumsy.

I wanted a one-command solution that bundles these pieces together. That’s how `ffl` was born.

---

### Why WebRTC, and why not just tunnel everything?

Sending large files and folders purely through tunnels isn’t ideal:

- Server storage is expensive.
- Zipping/tarring first is slow, and requires extra disk space.
- Pushing everything through a relay path is often unnecessary and inefficient.

If we can use **WebRTC** to stream files directly between peers, that’s much better — especially because browsers can talk WebRTC natively.

Another motivation: this tool is genuinely useful day-to-day, especially when you need to send tens or hundreds of gigabytes (see blog: *How FastFileLink Was Born*).  
But real life is messy: sometimes the other side cannot be online at the same time as you. In that case, the **temporary upload to server** feature becomes necessary (see blog: *How Do You Send a 50GB Holiday Photo Album?*).

---

### Porting to Cosmopolitan Libc (APE)

A big driver behind the Cosmopolitan Libc / APE work was very simple:  
I wanted a way to send my phone photos to my family easily, on almost any device 😅

To get `ffl` running as an APE:

- I removed all C-extension dependencies on `libffi` / `ctypes` and compiled them directly into the Python core.
- I added abstraction layers around all crypto logic so that I can switch between `cryptography` and `python-mbedtls` cleanly.
- The `cryptography` package relies on Rust and isn’t straightforward to integrate into Cosmopolitan Libc, so I switched to an mbedTLS-based approach instead.
- On Android, I ran the APE-flavored Python inside Termux and fixed a few strange networking behaviors.
- After that, I could finally bundle the entire Python project into a single APE executable.

---

## Open Source & Contributing

This repository provides the **open-source FastFileLink CLI**, licensed under the **Apache License 2.0**.

The following components are **not open source** (at least for now):

- GUI and Upload addons  
- Upload server and APIs

You may notice that even though these parts are not present in this open-source repo, the executable you download might still show that certain addons are “loaded”. That’s because:

- I want you to be able to **turn on upload features at any time**.
- If you already have an account, you can use them immediately.
- And honestly, if you like the tool, I hope you’ll consider supporting the project 🙂

If you prefer an executable that behaves **strictly identical** to what is in this open-source repo, you have a few options:

- Download `fflo.com` (a CLI-only APE build), or  
- Build a native version yourself directly from this source.

You can also control addons via configuration. For example, ```echo '{"disabled": ["API"]}' > ~/.fastfilelink/addons.json```


Without the API addon, other addons that depend on it cannot load either.  
This gives you an executable whose behavior matches the open-source version exactly.

If you are not interested in anything beyond the free version, but still want to support the project, you can also sponsor it on GitHub.  
Either way, I’ll keep maintaining and improving `ffl`. 💙

---

## Acknowledgements

FastFileLink has gone through many iterations and stands on the shoulders of a lot of great work. Special thanks to:

- [aiortc](https://github.com/aiortc/aiortc)  
- [Cosmopolitan Libc](https://github.com/jart/cosmopolitan)  
- [superconfigure](https://github.com/jart/superconfigure)  
- [mbedtls](https://github.com/Mbed-TLS/mbedtls)  

…and everyone who has tested the tool, reported bugs, suggested improvements, or simply used it in creative ways. 🙏
