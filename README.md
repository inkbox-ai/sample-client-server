# sample-client-server

An example self-hosted webhook receiver for [Inkbox](https://inkbox.ai). Verifies signatures with the `inkbox` SDK, spools payloads to disk, and logs a domain-aware summary. Also ships a WebSocket server for Inkbox phone media streams (Inkbox-managed TTS + STT). Bring your own downstream intelligence.

## Configuration

Copy `.env.example` to `.env` and fill in your values — at minimum `INKBOX_SIGNING_KEY`. When running in Docker you can skip the `.env` file and pass the same variables via `-e` flags; `config.py` reads from `os.environ` and treats `.env` as optional.

## Run with Docker (recommended)

```sh
docker build -t inkbox-webhook .
docker run --rm -p 8080:8080 \
  -e INKBOX_SIGNING_KEY=whsec_... \
  -e INKBOX_API_KEY=ApiKey_... \
  -v "$PWD/spool:/app/spool" \
  inkbox-webhook
```

The container runs `inkbox-webhook` on port 8080 and writes received payloads to `/app/spool` (mount a host directory if you want to read them from outside the container).

To run the phone media-stream WebSocket server instead, override the command and expose port 8090:

```sh
docker run --rm -p 8090:8090 \
  -e INKBOX_SIGNING_KEY=whsec_... \
  inkbox-webhook inkbox-phone-media
```

## Run locally without Docker

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
uv sync
```

### 3. Run

```sh
uv run inkbox-webhook       # webhook receiver on :8080
uv run inkbox-phone-media   # phone media WebSocket server on :8090
```

## Endpoints

- `POST /webhook` — Inkbox webhook receiver. Verifies the `X-Inkbox-Signature` header via `inkbox.verify_webhook`, spools the payload to `spool/<ts>.json`, and returns `200 OK` (or a phone action body for `incoming_call` events).
- `GET /health` — liveness check.

All paths can be prefixed via `PATH_PREFIX` (e.g. `PATH_PREFIX=alex` → `POST /alex/webhook`).
