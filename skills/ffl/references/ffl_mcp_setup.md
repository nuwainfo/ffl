# ffl-mcp Setup

Claude cannot install or run ffl-mcp from this sandboxed session. Run the steps below on your own computer.

## Step 1 — Install ffl (if not already)

**Linux / macOS:** `curl -fsSL https://fastfilelink.com/install.sh | bash`
**Windows:** `iwr -useb https://fastfilelink.com/install.ps1 | iex`

## Step 2 — Install ffl-mcp

**Windows (GUI, easiest):** Download and run `ffl-mcp-setup.exe` from https://github.com/nuwainfo/ffl-mcp/releases/latest — it registers with Claude automatically.

**Linux / macOS:**
```bash
curl -fsSL https://fastfilelink.com/mcp/install.sh | bash
```

**Windows (PowerShell):**
```powershell
iwr -useb https://fastfilelink.com/mcp/install.ps1 | iex
```

**Any platform (uvx):**
```bash
uvx --from git+https://github.com/nuwainfo/ffl-mcp install
```

## Step 3 — Restart Claude

Reload this session. Claude will then have `fflShareFile`, `fflDownload`, and related tools.
