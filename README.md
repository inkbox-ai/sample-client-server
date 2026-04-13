# inkbox-openclaw-server

An example self-hosted server for Inkbox and OpenClaw

## Setup

### 1. Install `uv`

**Linux / macOS:**
```sh
curl -LsSf https://astral.sh/uv/install.sh | sh
```

**Windows (PowerShell):**
```powershell
powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"
```

### 2. Install dependencies

```sh
uv lock              # resolve and write uv.lock
uv sync              # create .venv and install from the lock
uv pip install -e .  # editable install of this project
```
