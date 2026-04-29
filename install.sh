#!/usr/bin/env bash
set -euo pipefail

APP_NAME="homecom"
APP_DIR="/opt/homecom"
APP_USER="homecom"
APP_GROUP="homecom"
SERVICE_FILE="/etc/systemd/system/homecom.service"
DEFAULT_PORT="443"

if [[ $EUID -ne 0 ]]; then
  echo "Run as root: sudo bash install.sh"
  exit 1
fi

echo "HomeCom Intercom Installer"
echo

read -rp "Install directory [/opt/homecom]: " INPUT_APP_DIR
APP_DIR="${INPUT_APP_DIR:-$APP_DIR}"

read -rp "HTTPS port [${DEFAULT_PORT}]: " INPUT_PORT
PORT="${INPUT_PORT:-$DEFAULT_PORT}"

read -rp "Certificate hostname/IP [homecom]: " INPUT_HOSTNAME
CERT_HOSTNAME="${INPUT_HOSTNAME:-homecom}"

read -rp "Admin username [admin]: " INPUT_ADMIN
ADMIN_USER="${INPUT_ADMIN:-admin}"

while true; do
  read -rsp "Admin password: " ADMIN_PASS
  echo
  read -rsp "Confirm admin password: " ADMIN_PASS2
  echo
  [[ "$ADMIN_PASS" == "$ADMIN_PASS2" && -n "$ADMIN_PASS" ]] && break
  echo "Passwords did not match or were empty. Try again."
done

apt-get update
apt-get install -y python3 python3-venv python3-pip openssl libcap2-bin

if ! getent group "$APP_GROUP" >/dev/null 2>&1; then
  groupadd --system "$APP_GROUP"
fi

if ! id "$APP_USER" >/dev/null 2>&1; then
  useradd --system --gid "$APP_GROUP" --home "$APP_DIR" --shell /usr/sbin/nologin "$APP_USER"
fi

mkdir -p "$APP_DIR"/{static,certs,data}
chown -R "$APP_USER:$APP_GROUP" "$APP_DIR"

python3 -m venv "$APP_DIR/venv"
"$APP_DIR/venv/bin/pip" install --upgrade pip wheel
"$APP_DIR/venv/bin/pip" install fastapi uvicorn[standard] python-multipart

if (( PORT < 1024 )); then
  echo "Port $PORT is privileged. Granting CAP_NET_BIND_SERVICE..."
  PY_BIN="$(readlink -f "$APP_DIR/venv/bin/python3")"

  if [[ -f "$PY_BIN" ]]; then
    setcap 'cap_net_bind_service=+ep' "$PY_BIN"
    getcap "$PY_BIN" || true
  else
    echo "ERROR: Python binary not found at $PY_BIN"
    exit 1
  fi
fi

cat > "$APP_DIR/server.py" <<'PY'
import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import time
from pathlib import Path
from typing import Dict, Optional

from fastapi import FastAPI, Form, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, RedirectResponse, FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

APP_DIR = Path(os.environ.get("HOMECOM_APP_DIR", "/opt/homecom"))
DATA_DIR = APP_DIR / "data"
USERS_FILE = DATA_DIR / "users.json"
SECRET_FILE = DATA_DIR / "secret.key"
STATIC_DIR = APP_DIR / "static"

SESSION_TTL_SECONDS = 60 * 60 * 24 * 7

app = FastAPI()
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

clients: Dict[str, dict] = {}
active_talker: Optional[str] = None


def load_secret() -> bytes:
    if not SECRET_FILE.exists():
        SECRET_FILE.write_text(secrets.token_hex(64))
        os.chmod(SECRET_FILE, 0o600)
    return SECRET_FILE.read_text().strip().encode()


SECRET = load_secret()


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def unb64url(data: str) -> bytes:
    pad = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + pad)


def hash_password(password: str, salt: Optional[str] = None) -> dict:
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode(),
        bytes.fromhex(salt),
        250_000,
    )
    return {"salt": salt, "hash": digest.hex(), "scheme": "pbkdf2_sha256"}


def verify_password(password: str, record: dict) -> bool:
    candidate = hash_password(password, record["salt"])["hash"]
    return hmac.compare_digest(candidate, record["hash"])


def load_users() -> dict:
    if not USERS_FILE.exists():
        return {}
    return json.loads(USERS_FILE.read_text())


def save_users(users: dict):
    USERS_FILE.write_text(json.dumps(users, indent=2))
    os.chmod(USERS_FILE, 0o600)


def is_admin(username: str) -> bool:
    users = load_users()
    return bool(users.get(username, {}).get("admin", False))


def valid_username(username: str) -> bool:
    return bool(re.fullmatch(r"[A-Za-z0-9_.-]{2,32}", username))


def sign_session(username: str) -> str:
    payload = json.dumps(
        {"u": username, "iat": int(time.time())},
        separators=(",", ":"),
    ).encode()
    payload_b64 = b64url(payload)
    sig = hmac.new(SECRET, payload_b64.encode(), hashlib.sha256).digest()
    return f"{payload_b64}.{b64url(sig)}"


def read_session(token: str) -> Optional[str]:
    try:
        payload_b64, sig_b64 = token.split(".", 1)
        expected = hmac.new(SECRET, payload_b64.encode(), hashlib.sha256).digest()
        if not hmac.compare_digest(expected, unb64url(sig_b64)):
            return None
        payload = json.loads(unb64url(payload_b64))
        if int(time.time()) - int(payload["iat"]) > SESSION_TTL_SECONDS:
            return None
        username = payload["u"]
        if username not in load_users():
            return None
        return username
    except Exception:
        return None


def current_user(request: Request) -> Optional[str]:
    token = request.cookies.get("homecom_session")
    return read_session(token) if token else None


async def broadcast(message: dict):
    dead = []
    for cid, info in clients.items():
        try:
            await info["ws"].send_json(message)
        except Exception:
            dead.append(cid)
    for cid in dead:
        clients.pop(cid, None)


async def send_peer_list():
    await broadcast(
        {
            "type": "peers",
            "peers": [
                {"id": cid, "name": info["name"]}
                for cid, info in clients.items()
            ],
        }
    )


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    if not current_user(request):
        return RedirectResponse("/login", status_code=302)
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/login", response_class=HTMLResponse)
async def login_page():
    return FileResponse(STATIC_DIR / "login.html")


@app.post("/login")
async def login(username: str = Form(...), password: str = Form(...)):
    users = load_users()
    if username not in users or not verify_password(password, users[username]):
        return HTMLResponse("Invalid login. <a href='/login'>Try again</a>", status_code=401)

    response = RedirectResponse("/", status_code=302)
    response.set_cookie(
        "homecom_session",
        sign_session(username),
        httponly=True,
        secure=True,
        samesite="strict",
        max_age=SESSION_TTL_SECONDS,
    )
    return response


@app.post("/logout")
async def logout():
    response = RedirectResponse("/login", status_code=302)
    response.delete_cookie("homecom_session")
    return response


@app.get("/api/me")
async def me(request: Request):
    user = current_user(request)
    if not user:
        return JSONResponse({"authenticated": False}, status_code=401)

    return {
        "authenticated": True,
        "username": user,
        "admin": is_admin(user),
    }


@app.get("/api/users")
async def list_users(request: Request):
    user = current_user(request)
    if not user or not is_admin(user):
        return JSONResponse({"error": "admin required"}, status_code=403)

    users = load_users()
    return {
        "users": [
            {"username": name, "admin": bool(record.get("admin", False))}
            for name, record in sorted(users.items())
        ]
    }


@app.post("/api/users")
async def add_user(request: Request):
    user = current_user(request)
    if not user or not is_admin(user):
        return JSONResponse({"error": "admin required"}, status_code=403)

    body = await request.json()
    username = str(body.get("username", "")).strip()
    password = str(body.get("password", ""))
    admin = bool(body.get("admin", False))

    if not valid_username(username):
        return JSONResponse({"error": "username must be 2-32 chars: letters, numbers, dot, dash, underscore"}, status_code=400)

    if len(password) < 6:
        return JSONResponse({"error": "password must be at least 6 characters"}, status_code=400)

    users = load_users()
    record = hash_password(password)
    record["admin"] = admin
    users[username] = record
    save_users(users)

    return {"ok": True}


@app.post("/api/users/password")
async def change_user_password(request: Request):
    user = current_user(request)
    if not user or not is_admin(user):
        return JSONResponse({"error": "admin required"}, status_code=403)

    body = await request.json()
    username = str(body.get("username", "")).strip()
    password = str(body.get("password", ""))

    users = load_users()
    if username not in users:
        return JSONResponse({"error": "user not found"}, status_code=404)

    if len(password) < 6:
        return JSONResponse({"error": "password must be at least 6 characters"}, status_code=400)

    admin = bool(users[username].get("admin", False))
    users[username] = hash_password(password)
    users[username]["admin"] = admin
    save_users(users)

    return {"ok": True}


@app.delete("/api/users/{username}")
async def delete_user(username: str, request: Request):
    user = current_user(request)
    if not user or not is_admin(user):
        return JSONResponse({"error": "admin required"}, status_code=403)

    users = load_users()
    if username not in users:
        return JSONResponse({"error": "user not found"}, status_code=404)

    if username == user:
        return JSONResponse({"error": "cannot delete yourself"}, status_code=400)

    admin_users = [u for u, r in users.items() if r.get("admin", False)]
    if username in admin_users and len(admin_users) <= 1:
        return JSONResponse({"error": "cannot delete the last admin"}, status_code=400)

    del users[username]
    save_users(users)

    return {"ok": True}


@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    global active_talker

    await ws.accept()

    token = ws.cookies.get("homecom_session")
    username = read_session(token) if token else None
    if not username:
        await ws.close(code=4401)
        return

    cid = secrets.token_hex(8)
    clients[cid] = {"ws": ws, "name": username}
    await ws.send_json({"type": "hello", "id": cid, "name": username})
    await send_peer_list()

    try:
        while True:
            msg = await ws.receive_json()
            msg_type = msg.get("type")

            if msg_type in {"offer", "answer", "candidate"}:
                target = msg.get("target")
                if target in clients:
                    msg["source"] = cid
                    msg["sourceName"] = username
                    await clients[target]["ws"].send_json(msg)

            elif msg_type == "talk-request":
                if active_talker in clients and active_talker != cid:
                    await ws.send_json(
                        {
                            "type": "talk-denied",
                            "talker": active_talker,
                            "talkerName": clients[active_talker]["name"],
                        }
                    )
                else:
                    active_talker = cid
                    await broadcast(
                        {
                            "type": "talk-start",
                            "talker": cid,
                            "talkerName": username,
                        }
                    )

            elif msg_type == "talk-stop":
                if active_talker == cid:
                    active_talker = None
                    await broadcast(
                        {
                            "type": "talk-stop",
                            "talker": cid,
                            "talkerName": username,
                        }
                    )

            elif msg_type == "ping":
                await ws.send_json({"type": "pong"})

    except WebSocketDisconnect:
        pass
    finally:
        clients.pop(cid, None)
        if active_talker == cid:
            active_talker = None
            await broadcast({"type": "talk-stop", "talker": cid, "talkerName": username})
        await send_peer_list()
PY

cat > "$APP_DIR/static/login.html" <<'HTML'
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>HomeCom Login</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link href="/static/style.css" rel="stylesheet">
</head>
<body>
  <main class="login-wrap">
    <form class="card login-card" method="post" action="/login">
      <h1>HomeCom</h1>
      <p>House intercom login</p>
      <label>Username</label>
      <input name="username" autocomplete="username" required>
      <label>Password</label>
      <input name="password" type="password" autocomplete="current-password" required>
      <button type="submit">Login</button>
    </form>
  </main>
</body>
</html>
HTML

cat > "$APP_DIR/static/index.html" <<'HTML'
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>HomeCom</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link href="/static/style.css" rel="stylesheet">
</head>
<body>
  <header>
    <div>
      <h1>HomeCom</h1>
      <span id="status">Starting...</span>
    </div>
    <form method="post" action="/logout">
      <button class="secondary" type="submit">Logout</button>
    </form>
  </header>

  <main>
    <section class="card">
      <h2>Push to Talk</h2>
      <button id="ptt" disabled>Hold to Talk</button>
      <p id="talker">No active talker</p>
    </section>

    <section class="card">
      <h2>Devices</h2>
      <ul id="peers"></ul>
    </section>

    <section class="card">
      <h2>Audio</h2>
      <p id="browserHelp">Tap Join once on each device to allow microphone and speaker playback.</p>
      <button id="join">Join Intercom</button>
      <p id="audioState">Audio not joined.</p>
    </section>

    <section id="usersCard" class="card hidden">
      <h2>Users</h2>

      <div class="user-form">
        <input id="newUser" placeholder="Username">
        <input id="newPass" placeholder="Password" type="password">
        <label class="checkrow">
          <input id="newAdmin" type="checkbox">
          Admin
        </label>
        <button id="addUser" type="button">Add / Update User</button>
      </div>

      <ul id="userList"></ul>
    </section>
  </main>

  <div id="audio"></div>
  <script src="/static/app.js"></script>
</body>
</html>
HTML

cat > "$APP_DIR/static/style.css" <<'CSS'
:root {
  color-scheme: dark;
  --bg: #09110b;
  --panel: #101b13;
  --border: #2c4a32;
  --text: #eef8ef;
  --muted: #9eb7a3;
  --accent: #8ee68e;
  --danger: #ff6b6b;
}

* {
  box-sizing: border-box;
}

body {
  margin: 0;
  font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
  background: radial-gradient(circle at top, #142117, var(--bg));
  color: var(--text);
}

header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 18px 22px;
  border-bottom: 1px solid var(--border);
  background: rgba(8, 16, 10, 0.86);
}

h1, h2 {
  margin: 0 0 8px 0;
}

header h1 {
  margin: 0;
}

#status, .card p, label {
  color: var(--muted);
}

#audioState {
  font-weight: 700;
}

main {
  display: grid;
  grid-template-columns: 1.2fr 1fr;
  gap: 18px;
  padding: 18px;
  max-width: 1100px;
  margin: 0 auto;
}

.card {
  border: 1px solid var(--border);
  background: rgba(16, 27, 19, 0.88);
  border-radius: 16px;
  padding: 18px;
  box-shadow: 0 18px 45px rgba(0,0,0,0.32);
}

.card:first-child {
  grid-row: span 2;
}

.hidden {
  display: none;
}

#ptt {
  width: 100%;
  min-height: 190px;
  border-radius: 24px;
  font-size: clamp(28px, 6vw, 56px);
  font-weight: 800;
  background: linear-gradient(180deg, #234d28, #112915);
  border: 2px solid var(--accent);
  color: var(--text);
  touch-action: none;
  user-select: none;
}

#ptt.talking {
  background: linear-gradient(180deg, #6b1717, #331010);
  border-color: var(--danger);
}

button {
  cursor: pointer;
  border: 1px solid var(--border);
  background: #17291b;
  color: var(--text);
  border-radius: 10px;
  padding: 12px 16px;
  font-weight: 700;
}

button:disabled {
  opacity: 0.45;
  cursor: not-allowed;
}

button.secondary {
  background: transparent;
}

ul {
  padding-left: 20px;
}

li {
  margin: 8px 0;
}

.login-wrap {
  display: grid;
  place-items: center;
  min-height: 100vh;
}

.login-card {
  width: min(420px, calc(100vw - 32px));
}

input {
  width: 100%;
  padding: 12px;
  margin: 6px 0 14px 0;
  border-radius: 10px;
  border: 1px solid var(--border);
  background: #08100a;
  color: var(--text);
}

.user-form {
  display: grid;
  gap: 10px;
}

.checkrow {
  display: flex;
  align-items: center;
  gap: 8px;
}

.checkrow input {
  width: auto;
  margin: 0;
}

.user-row {
  display: grid;
  grid-template-columns: 1fr;
  gap: 8px;
  align-items: center;
  margin-bottom: 14px;
  padding-bottom: 14px;
  border-bottom: 1px solid var(--border);
}

.user-actions {
  display: flex;
  gap: 8px;
  flex-wrap: wrap;
}

.user-row input {
  margin: 0;
}

@media (max-width: 760px) {
  main {
    grid-template-columns: 1fr;
  }

  .card:first-child {
    grid-row: auto;
  }
}
CSS

cat > "$APP_DIR/static/app.js" <<'JS'
let ws;
let myId = null;
let myName = null;
let localStream = null;
let joined = false;
let peers = new Map();
let peerNames = new Map();
let talking = false;
let audioCtx = null;
let currentUser = null;
let knownUsers = [];

const statusEl = document.getElementById("status");
const peersEl = document.getElementById("peers");
const ptt = document.getElementById("ptt");
const joinBtn = document.getElementById("join");
const talkerEl = document.getElementById("talker");
const audioRoot = document.getElementById("audio");
const audioStateEl = document.getElementById("audioState");
const browserHelpEl = document.getElementById("browserHelp");

const usersCard = document.getElementById("usersCard");
const userSelectEl = document.getElementById("userSelect");
const newUserEl = document.getElementById("newUser");
const newPassEl = document.getElementById("newPass");
const newAdminEl = document.getElementById("newAdmin");
const addUserBtn = document.getElementById("addUser");
const changePassBtn = document.getElementById("changePass");
const deleteUserBtn = document.getElementById("deleteUser");
const adminStateEl = document.getElementById("adminState");

function setStatus(text) {
  statusEl.textContent = text;
}

function setAudioState(text) {
  audioStateEl.textContent = text;
}

function setAdminState(text) {
  if (adminStateEl) adminStateEl.textContent = text;
}

function isiOS() {
  return /iPad|iPhone|iPod/.test(navigator.userAgent) ||
    (navigator.platform === "MacIntel" && navigator.maxTouchPoints > 1);
}

function isChromeiOS() {
  return /CriOS/.test(navigator.userAgent);
}

function setBrowserHelp() {
  if (isChromeiOS()) {
    browserHelpEl.textContent = "Chrome on iOS may block mic/WebRTC with local self-signed certs. Safari is recommended.";
  } else if (isiOS()) {
    browserHelpEl.textContent = "iOS Safari: tap Join, allow microphone, and keep the HomeCom cert fully trusted.";
  }
}

function micErrorMessage(err) {
  const base = err && err.message ? err.message : String(err);

  if (!window.isSecureContext) {
    return "Not a secure context. Install and fully trust the HomeCom cert, then reload HTTPS.";
  }

  if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
    return "Microphone API unavailable. On iOS, use Safari with the HomeCom cert installed and trusted.";
  }

  return `Could not join intercom: ${base}`;
}

async function unlockAudio() {
  try {
    const AudioContextClass = window.AudioContext || window.webkitAudioContext;
    if (AudioContextClass) {
      audioCtx = audioCtx || new AudioContextClass();
      if (audioCtx.state === "suspended") await audioCtx.resume();

      const oscillator = audioCtx.createOscillator();
      const gain = audioCtx.createGain();
      gain.gain.value = 0.00001;
      oscillator.connect(gain);
      gain.connect(audioCtx.destination);
      oscillator.start();
      oscillator.stop(audioCtx.currentTime + 0.03);
    }
  } catch (e) {
    console.warn("Audio unlock warning:", e);
  }
}

function renderPeers(peerList) {
  peersEl.innerHTML = "";
  peerList.forEach(peer => {
    peerNames.set(peer.id, peer.name);
    const li = document.createElement("li");
    li.textContent = peer.id === myId ? `${peer.name} (you)` : peer.name;
    peersEl.appendChild(li);
  });
}

function ensureAudio(peerId, stream) {
  let audio = document.getElementById(`audio-${peerId}`);
  if (!audio) {
    audio = document.createElement("audio");
    audio.id = `audio-${peerId}`;
    audio.autoplay = true;
    audio.playsInline = true;
    audio.setAttribute("playsinline", "true");
    audioRoot.appendChild(audio);
  }

  audio.srcObject = stream;
  audio.muted = false;
  audio.volume = 1.0;

  audio.play()
    .then(() => setAudioState("Remote audio active."))
    .catch(err => {
      console.warn("Audio play blocked:", err);
      setAudioState("Remote audio connected, but playback was blocked. Tap Join again.");
    });
}

async function createPeerConnection(peerId) {
  if (peerId === myId) return null;
  if (peers.has(peerId)) return peers.get(peerId);

  const pc = new RTCPeerConnection({ iceServers: [] });
  peers.set(peerId, pc);

  if (localStream) {
    localStream.getTracks().forEach(track => pc.addTrack(track, localStream));
  }

  pc.ontrack = event => ensureAudio(peerId, event.streams[0]);

  pc.onicecandidate = event => {
    if (event.candidate && ws && ws.readyState === WebSocket.OPEN) {
      ws.send(JSON.stringify({
        type: "candidate",
        target: peerId,
        candidate: event.candidate
      }));
    }
  };

  pc.onconnectionstatechange = () => {
    if (["failed", "closed", "disconnected"].includes(pc.connectionState)) {
      peers.delete(peerId);
    }
  };

  return pc;
}

async function callPeer(peerId) {
  const pc = await createPeerConnection(peerId);
  if (!pc) return;

  const offer = await pc.createOffer();
  await pc.setLocalDescription(offer);
  ws.send(JSON.stringify({
    type: "offer",
    target: peerId,
    sdp: pc.localDescription
  }));
}

async function handleOffer(msg) {
  const pc = await createPeerConnection(msg.source);
  await pc.setRemoteDescription(new RTCSessionDescription(msg.sdp));
  const answer = await pc.createAnswer();
  await pc.setLocalDescription(answer);
  ws.send(JSON.stringify({
    type: "answer",
    target: msg.source,
    sdp: pc.localDescription
  }));
}

async function handleAnswer(msg) {
  const pc = peers.get(msg.source);
  if (pc) await pc.setRemoteDescription(new RTCSessionDescription(msg.sdp));
}

async function handleCandidate(msg) {
  const pc = peers.get(msg.source);
  if (pc && msg.candidate) {
    try {
      await pc.addIceCandidate(new RTCIceCandidate(msg.candidate));
    } catch (e) {
      console.warn("ICE candidate error:", e);
    }
  }
}

async function joinIntercom() {
  if (joined) return;

  setAudioState("Joining audio...");

  if (!window.isSecureContext) {
    throw new Error("not secure/trusted HTTPS");
  }

  if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
    throw new Error("getUserMedia unavailable");
  }

  await unlockAudio();

  localStream = await navigator.mediaDevices.getUserMedia({
    audio: {
      echoCancellation: true,
      noiseSuppression: true,
      autoGainControl: true
    },
    video: false
  });

  localStream.getAudioTracks().forEach(track => {
    track.enabled = true;
  });

  setTimeout(() => {
    if (!talking && localStream) {
      localStream.getAudioTracks().forEach(track => {
        track.enabled = false;
      });
    }
  }, 400);

  joined = true;
  ptt.disabled = false;
  joinBtn.textContent = "Audio Joined";
  setStatus(`Connected as ${myName || "user"}`);
  setAudioState("Audio joined. Hold Push to Talk to transmit.");

  for (const peerId of peerNames.keys()) {
    if (peerId !== myId) await callPeer(peerId);
  }
}

function connectWs() {
  ws = new WebSocket(`wss://${location.host}/ws`);

  ws.onopen = () => setStatus("Connected. Tap Join.");

  ws.onclose = () => {
    setStatus("Disconnected. Reconnecting...");
    ptt.disabled = true;
    setTimeout(connectWs, 1500);
  };

  ws.onerror = () => setStatus("WebSocket error.");

  ws.onmessage = async event => {
    const msg = JSON.parse(event.data);

    if (msg.type === "hello") {
      myId = msg.id;
      myName = msg.name;
      setStatus(`Connected as ${myName}. Tap Join.`);
    }

    if (msg.type === "peers") {
      renderPeers(msg.peers);
      if (joined) {
        for (const peer of msg.peers) {
          if (peer.id !== myId && !peers.has(peer.id)) await callPeer(peer.id);
        }
      }
    }

    if (msg.type === "offer") await handleOffer(msg);
    if (msg.type === "answer") await handleAnswer(msg);
    if (msg.type === "candidate") await handleCandidate(msg);

    if (msg.type === "talk-start") {
      talkerEl.textContent = `${msg.talkerName} is talking`;
      if (msg.talker !== myId) ptt.disabled = true;
    }

    if (msg.type === "talk-stop") {
      talkerEl.textContent = "No active talker";
      if (joined) ptt.disabled = false;
    }

    if (msg.type === "talk-denied") {
      talkerEl.textContent = `${msg.talkerName} is already talking`;
      stopTalkingLocalOnly();
    }
  };
}

function startTalking() {
  if (!joined || talking || !localStream) return;
  talking = true;
  ptt.classList.add("talking");
  ptt.textContent = "Talking...";
  localStream.getAudioTracks().forEach(track => track.enabled = true);
  ws.send(JSON.stringify({ type: "talk-request" }));
}

function stopTalkingLocalOnly() {
  talking = false;
  ptt.classList.remove("talking");
  ptt.textContent = "Hold to Talk";
  if (localStream) {
    localStream.getAudioTracks().forEach(track => track.enabled = false);
  }
}

function stopTalking() {
  if (!talking) return;
  stopTalkingLocalOnly();
  ws.send(JSON.stringify({ type: "talk-stop" }));
}

async function apiJson(url, options = {}) {
  const res = await fetch(url, {
    headers: {"Content-Type": "application/json"},
    ...options
  });

  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
  return data;
}

async function loadMe() {
  currentUser = await apiJson("/api/me");

  if (currentUser.admin && usersCard) {
    usersCard.classList.remove("hidden");
    await loadUsers();
  } else if (usersCard) {
    usersCard.remove();
  }
}

function renderUserDropdown() {
  userSelectEl.innerHTML = "";

  knownUsers.forEach(user => {
    const opt = document.createElement("option");
    opt.value = user.username;
    opt.textContent = `${user.username}${user.admin ? " (admin)" : ""}`;
    userSelectEl.appendChild(opt);
  });
}

async function loadUsers() {
  if (!userSelectEl) return;

  const data = await apiJson("/api/users");
  knownUsers = data.users;
  renderUserDropdown();
  setAdminState(`Loaded ${knownUsers.length} user(s).`);
}

function selectedUsername() {
  return userSelectEl ? userSelectEl.value : "";
}

if (userSelectEl) {
  userSelectEl.addEventListener("change", () => {
    const user = knownUsers.find(u => u.username === userSelectEl.value);
    if (!user) return;
    newUserEl.value = user.username;
    newAdminEl.checked = !!user.admin;
    newPassEl.value = "";
  });
}

if (addUserBtn) {
  addUserBtn.addEventListener("click", async () => {
    try {
      await apiJson("/api/users", {
        method: "POST",
        body: JSON.stringify({
          username: newUserEl.value,
          password: newPassEl.value,
          admin: newAdminEl.checked
        })
      });

      newPassEl.value = "";
      await loadUsers();
      setAdminState("User added/updated.");
    } catch (err) {
      alert(err.message);
    }
  });
}

if (changePassBtn) {
  changePassBtn.addEventListener("click", async () => {
    try {
      const username = selectedUsername();
      if (!username) return alert("Select a user.");
      if (!newPassEl.value) return alert("Enter a new password.");

      await apiJson("/api/users/password", {
        method: "POST",
        body: JSON.stringify({
          username,
          password: newPassEl.value
        })
      });

      newPassEl.value = "";
      setAdminState("Password changed.");
    } catch (err) {
      alert(err.message);
    }
  });
}

if (deleteUserBtn) {
  deleteUserBtn.addEventListener("click", async () => {
    try {
      const username = selectedUsername();
      if (!username) return alert("Select a user.");
      if (!confirm(`Delete user ${username}?`)) return;

      await apiJson(`/api/users/${encodeURIComponent(username)}`, {
        method: "DELETE"
      });

      await loadUsers();
      setAdminState("User deleted.");
    } catch (err) {
      alert(err.message);
    }
  });
}

joinBtn.addEventListener("click", async () => {
  try {
    await joinIntercom();
  } catch (err) {
    const msg = micErrorMessage(err);
    setAudioState(msg);
    alert(msg);
  }
});

ptt.addEventListener("pointerdown", event => {
  event.preventDefault();
  unlockAudio();
  startTalking();
});

ptt.addEventListener("pointerup", event => {
  event.preventDefault();
  stopTalking();
});

ptt.addEventListener("pointercancel", stopTalking);
ptt.addEventListener("pointerleave", stopTalking);

window.addEventListener("beforeunload", stopTalking);

setBrowserHelp();
connectWs();
loadMe().catch(err => console.warn("loadMe failed:", err));
JS

python3 - <<PY
import json, hashlib, secrets
from pathlib import Path

app_dir = Path("$APP_DIR")
data_dir = app_dir / "data"
users_file = data_dir / "users.json"

username = "$ADMIN_USER"
password = """$ADMIN_PASS"""

salt = secrets.token_hex(16)
digest = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), 250000).hex()

users = {}
if users_file.exists():
    users = json.loads(users_file.read_text())

users[username] = {
    "salt": salt,
    "hash": digest,
    "scheme": "pbkdf2_sha256",
    "admin": True
}

users_file.write_text(json.dumps(users, indent=2))
PY

if [[ ! -f "$APP_DIR/data/secret.key" ]]; then
  openssl rand -hex 64 > "$APP_DIR/data/secret.key"
fi

IP_ADDR="$(hostname -I | awk '{print $1}')"

SAN_LIST="DNS:${CERT_HOSTNAME},DNS:homecom.local,DNS:homecom,IP:127.0.0.1"
if [[ -n "$IP_ADDR" ]]; then
  SAN_LIST="${SAN_LIST},IP:${IP_ADDR}"
fi

if [[ "$CERT_HOSTNAME" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  SAN_LIST="${SAN_LIST},IP:${CERT_HOSTNAME}"
fi

openssl req -x509 -newkey rsa:4096 -sha256 -days 3650 -nodes \
  -keyout "$APP_DIR/certs/homecom.key" \
  -out "$APP_DIR/certs/homecom.crt" \
  -subj "/CN=$CERT_HOSTNAME" \
  -addext "subjectAltName=${SAN_LIST}" >/dev/null 2>&1

cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=HomeCom Household Intercom
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$APP_USER
Group=$APP_GROUP
WorkingDirectory=$APP_DIR
Environment=HOMECOM_APP_DIR=$APP_DIR
ExecStart=$APP_DIR/venv/bin/uvicorn server:app --host 0.0.0.0 --port $PORT --ssl-keyfile $APP_DIR/certs/homecom.key --ssl-certfile $APP_DIR/certs/homecom.crt
Restart=always
RestartSec=3
NoNewPrivileges=false
PrivateTmp=true
ProtectSystem=full
ProtectHome=true
ReadWritePaths=$APP_DIR
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
EOF

chown -R "$APP_USER:$APP_GROUP" "$APP_DIR"
chmod 600 "$APP_DIR/data/secret.key" "$APP_DIR/data/users.json" "$APP_DIR/certs/homecom.key"
chmod 644 "$APP_DIR/certs/homecom.crt"

if command -v ufw >/dev/null 2>&1; then
  ufw allow "$PORT/tcp" || true
  ufw allow 8000/tcp || true
fi

systemctl daemon-reexec
systemctl daemon-reload
systemctl enable --now homecom.service
systemctl restart homecom.service

echo
echo "HomeCom installed."
echo "URL: https://${IP_ADDR}:${PORT}"
echo "Login: ${ADMIN_USER}"
echo
echo "iOS certificate install:"
echo "  1. On the Pi, run:"
echo "       cd $APP_DIR/certs"
echo "       python3 -m http.server 8000"
echo
echo "  2. On the iPhone/iPad, open Safari:"
echo "       http://${IP_ADDR}:8000/homecom.crt"
echo
echo "  3. Install the downloaded profile:"
echo "       Settings -> General -> VPN & Device Management"
echo
echo "  4. Fully trust it:"
echo "       Settings -> General -> About -> Certificate Trust Settings"
echo
echo "  5. Then open:"
echo "       https://${IP_ADDR}:${PORT}"
echo
echo "Notes:"
echo "  - Safari on iOS is the supported mobile browser."
echo "  - Chrome on iOS may still block WebRTC/mic access with self-signed local certs."
echo "  - Admin users can add/delete users and change passwords from the web UI."
echo
echo "Service commands:"
echo "  systemctl status homecom --no-pager"
echo "  journalctl -u homecom -f"
