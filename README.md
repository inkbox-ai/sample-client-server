# sample-client-server

An example self-hosted server for [Inkbox](https://inkbox.ai). A single FastAPI process handles both:

- **`POST /webhook`** — HTTP webhooks for mail events, incoming texts, and incoming calls. Signatures verified via the `inkbox` SDK; bodies parsed with Pydantic models; raw payloads written to `payloads/<ts>.json` for inspection.
- **`WebSocket /phone/media/ws`** — live phone-media sessions once a call is answered. Receives platform events from Inkbox (`start`, `transcript`, `barge_in`, `stop`) and sends outbound `text` frames for Inkbox-managed TTS to play back to the caller.

See `src/data_models/webhooks.py` and `src/data_models/phone_media.py` for the exact JSON shapes exchanged on each side — the app uses those same Pydantic models to validate incoming requests, so "what hits my endpoint" lives in one place.

## What you'll be able to do by the end

Once the steps below are done, your local server will be able to:

- **Receive emails** — inbound messages (and status notifications like delivered / bounced) land on `POST /webhook` and get persisted to `payloads/`.
- **Receive SMS and MMS** — inbound text messages (with attachments) hit the same `/webhook` endpoint.
- **Accept phone calls** — incoming calls are auto-answered and connected to a sample AI agent (`src/phone_agent.py`) that talks to the caller live over the phone-media WebSocket, using Inkbox-managed speech-to-text and text-to-speech.

## Prerequisites — set up your Inkbox org

Before running the server, provision an agent identity in the Inkbox console and collect four credentials. Steps:

### 1. Create the agent identity (with mailbox + phone number)

1. Go to [console.inkbox.ai](https://console.inkbox.ai) and sign in.
2. Open **Identities** → **New identity**. Pick a name for your agent (e.g. `demo-agent`).
3. During creation (or from the identity's detail page afterward), attach:
   - A **mailbox** — pick an email address on one of the available domains.
   - A **phone number** — provision a number in your region.
4. Save. The identity now owns one mailbox and one phone number; this server's bootstrap will patch both on startup.

### 2. Grab the Inkbox API key for the agent identity

On the identity's detail page, open **API keys** → **Create key**. Copy the key value (you won't see it again). This is your `INKBOX_API_KEY` — the bootstrap uses it to `list` + `update` the identity's phone numbers and mailboxes.

### 3. Grab the Inkbox webhook signing key

Go to [console.inkbox.ai/webhooks](https://inkbox.ai/console/webhooks) → **Create signing key**. Copy the `whsec_...` value. This is your `INKBOX_SIGNING_KEY` — used by this server to verify `X-Inkbox-Signature` on every inbound webhook and on the phone-media WebSocket handshake.

### 4. Pick an Inkbox tunnel name

Choose a subdomain label (lowercase, hyphens OK; e.g. `demo-acme`). On startup the bootstrap creates a tunnel under `{name}.development.inkboxwire.com` via the Inkbox tunnels API and persists the per-tunnel `connect_secret` (shown once) under `.inkbox-tunnel-state/`. This replaces the old ngrok flow — the tunnel is first-party and routes through a single persistent HTTP/2 connection from this process.

The default `INKBOX_TUNNEL_TLS_MODE=edge` lets Inkbox terminate TLS for you. Switch to `passthrough` if you want to hold the private key locally — the bootstrap will generate a keypair, submit a CSR via `POST /tunnels/{id}/sign-csr`, and persist the LE-signed cert chain alongside the key.

### 5. Grab an OpenAI API key

Create a key at [platform.openai.com/api-keys](https://platform.openai.com/api-keys). This is your `OPENAI_API_KEY` — the sample phone agent (`src/phone_agent.py`) uses it to generate live call replies.

### 6. Back in this repo: fill in `.env`

```sh
cp .env.example .env
chmod 600 .env
```

Open `.env` and paste in the four values you just collected:

```
INKBOX_API_KEY=...            # step 2
INKBOX_SIGNING_KEY=whsec_...  # step 3
INKBOX_TUNNEL_NAME=demo-acme  # step 4
OPENAI_API_KEY=sk-...         # step 5
```

That's it — you're ready to run. On startup the server will create the Inkbox tunnel (first run) or reuse it (subsequent runs), PATCH every phone number + mailbox on your identity to point at `{INKBOX_TUNNEL_NAME}.development.inkboxwire.com`, open the persistent HTTP/2 data-plane connection, and start serving webhooks + the phone-media WebSocket. The per-tunnel `connect_secret` is written once under `.inkbox-tunnel-state/` (chmod 600); for `passthrough` mode the private key + LE-signed cert chain live there too.

## Configuration notes

Signature verification is **on by default**. If you're testing locally without a real signing key, set `INKBOX_REQUIRE_SIGNATURE=false` — but then Inkbox won't be able to call you (the real platform always signs), so this is only useful for curl-based local testing.

When running in Docker you can skip the `.env` file and pass the same variables via `-e` flags; `env_config.py` reads from `os.environ` and treats `.env` as optional.

## Run with Docker (recommended)

The easiest way is the helper script, which builds and runs in one step:

```sh
./scripts/run_docker.py
# or: ./scripts/run_docker.py --host-port 9000 --image-name my-inkbox-server
```

Or do it by hand:

```sh
docker build -t inkbox-sample-client-server .
docker run --rm -p 8080:8080 \
  -e INKBOX_SIGNING_KEY=whsec_... \
  -v "$PWD/payloads:/app/payloads" \
  inkbox-sample-client-server
```

The container runs `inkbox-server` on port 8080 and writes received payloads to `/app/payloads` (mount a host directory if you want to read them from outside the container).

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
uv run inkbox-server   # webhooks + phone media WS on :8080
```

## Endpoints

- `POST /webhook` — Inkbox webhook receiver. Verifies `X-Inkbox-Signature` via `inkbox.verify_webhook`, parses the body into a `MailWebhookPayload`, `PhoneIncomingTextWebhookPayload`, or `PhoneIncomingCallWebhookPayload`, writes the raw payload to `payloads/<ts>.json`, and returns `200 OK` (or an `IncomingCallActionResponse` body for `incoming_call` events).
- `WebSocket /phone/media/ws` — Live phone-media session. Inkbox opens this once a call is answered; we optionally verify the handshake signature, accept with `X-Use-Inkbox-{Text-To-Speech,Speech-To-Text}: true` headers, and respond to final `transcript` frames with outbound `text` replies.
- `GET /health` — liveness check.
