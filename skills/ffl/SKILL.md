---
name: ffl
description: FastFileLink (ffl) assistant — detect environment, install ffl if needed, and help the user share files, download files, configure tunnels, set up E2EE/auth, and automate file-sharing workflows. Invoke whenever the user wants to share a file or folder, get a download link, receive a file from someone, protect a transfer with a password or encryption, limit downloads to one use, or do anything ffl/FastFileLink-related — even if they don't say "ffl" explicitly. Also trigger for phrases like "send this file", "give me a shareable link", "share these files securely", "someone needs to download X from me", "get me a one-time link", or "upload and share".
---

You are an expert on **ffl** (FastFileLink). Always give the user the exact command first, then handle execution.

## Step 1: Detect environment

Check your tool list for `fflShareFile`, `fflDownload`, etc. — if present, use them directly and skip the script.

Otherwise, run:
```bash
bash <SKILL_DIR>/scripts/detect_env.sh
```

| ADVICE | Action |
|---|---|
| `run_cli` | Run ffl commands in the shell |
| `install_then_run` | Install ffl (see below), then run |
| `give_command_sandbox` | Give the exact command + read and show `references/ffl_mcp_setup.md` |

---

## Install ffl (ADVICE=install_then_run)

**Linux / macOS:** `curl -fsSL https://fastfilelink.com/install.sh | bash`
**Windows:** `iwr -useb https://fastfilelink.com/install.ps1 | iex`
**Portable (all platforms):**
```bash
curl -fL https://github.com/nuwainfo/ffl/releases/latest/download/ffl.com -o ffl.com
chmod +x ffl.com && mv ffl.com ~/.local/bin/ffl
```

---

## Command reference

### Sharing
```bash
ffl file.pdf                    # single file
ffl a.pdf b.jpg c.txt           # multiple → auto-zipped
ffl myfolder/                   # folder (ZIP-streamed)
cat data.csv | ffl -            # stdin
ffl @filelist.txt               # one path per line

--name / -n NAME                custom filename for recipient
--exclude PATTERNS              '*.log,__pycache__' or 're:\.env$'
--upload [DURATION]             server upload: "1 day", "6 hours" — file stays available without keeping computer on (registered + costs points)
--resume                        resume interrupted upload
--max-downloads N               expire after N downloads (P2P)
--timeout SECONDS               expire after N idle seconds (P2P)
--e2ee                          end-to-end encryption (AES-256-GCM)
--auth-user / --auth-password   HTTP Basic Auth
--recipient-auth MODE           pickup | pubkey | pubkey+pickup | email
--pickup-code CODE              specific pickup code
--recipient-public-key FILE     .fflpub for pubkey auth
--alias ALIAS                   custom reusable link alias (registered + costs points)
--receipt [EMAIL]               email when recipient downloads (registered + costs points)
--receipt-confirm [MSG]         require recipient confirmation first
--force-relay                   disable direct WebRTC
--preferred-tunnel TUNNEL       save tunnel pref (cloudflare/ngrok/bore)
--qr [FILE]                     QR code in terminal or saved image
--json FILE                     output link+metadata to JSON (CI/CD)
```

### Downloading
```bash
ffl https://ffl.link/xxxx
ffl https://ffl.link/xxxx -o ~/Downloads/
ffl https://ffl.link/xxxx --resume
ffl https://ffl.link/xxxx --recipient-auth pickup --pickup-code 482910
ffl https://ffl.link/xxxx --recipient-auth pubkey --recipient-private-key alice.fflkey
```

### Account / misc
```bash
ffl register / ffl login / ffl status / ffl logout / ffl upgrade / ffl --version
--cli  --log-level LEVEL  --proxy URL  --hook URL
```

---

## Common scenarios

```bash
ffl secret.pdf --max-downloads 1                          # one-time link
ffl myfile.zip --upload "2 days"                          # server upload — no need to keep computer on (registered + points)
ffl sensitive.zip --upload "2 days" --e2ee                # zero-knowledge encrypted upload (registered + points)
ffl myfile.zip --e2ee                                     # E2EE P2P
ffl report.pdf --auth-user alice --auth-password s3cr3t   # password protect
ffl myfile.zip --recipient-auth pickup                    # pickup code gate
ffl keygen --name alice                                   # recipient generates keypair
ffl myfile.zip --recipient-auth pubkey --recipient-public-key alice.fflpub
ffl myfile.zip --proxy socks5://127.0.0.1:9050 --e2ee --force-relay   # Tor
ffl build.zip --alias my-project-release                  # reusable link (registered + points)
ffl myproject/ --exclude '*.pyc,__pycache__,.git,node_modules'
ffl myfile.zip --json /tmp/out.json                       # CI/CD
ffl photo.jpg --qr
```


When the user needs `--upload`, `--alias`, or `--receipt`, note that these require a registered account and cost points — suggest `ffl register` if they haven't signed up.
