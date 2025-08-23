import express from "express";
import cors from "cors";
import multer from "multer";
import { WebSocketServer } from "ws";
import crypto from "crypto";
import fs from "fs";
import { URL } from "url";
import config from "./config.js";
import {
  registerUser,
  authenticate,
  saveToken,
  validateToken,
  saveMessage,
  getMessages
} from "./storage/storage.js";

const app = express();
app.use(cors({ origin: config.cors.origin }));
app.use(express.json({ limit: "1mb" }));

if (config.features.uploads) {
  if (!fs.existsSync(config.uploads.dir)) fs.mkdirSync(config.uploads.dir, { recursive: true });
}

const upload = multer({
  dest: config.uploads.dir,
  limits: { fileSize: config.uploads.maxFileSize },
  fileFilter: (req, file, cb) => cb(null, config.uploads.allowedMime.includes(file.mimetype))
});

const wsClients = new Set();
const sseClients = new Set();

function genToken() {
  return crypto.randomBytes(32).toString("hex");
}

async function authMiddleware(req, res, next) {
  const auth = req.headers.authorization || "";
  const parts = auth.split(" ");
  if (parts.length !== 2 || parts[0] !== "Bearer") return res.status(401).json({ error: "no auth" });
  const user = await validateToken(parts[1]);
  if (!user) return res.status(401).json({ error: "invalid token" });
  req.user = user;
  next();
}

function limiter() {
  const hits = new Map();
  const windowMs = config.rateLimit.windowMs;
  const max = config.rateLimit.max;
  return (req, res, next) => {
    const now = Date.now();
    const ip = req.ip || req.connection.remoteAddress || "unknown";
    const arr = hits.get(ip) || [];
    const fresh = arr.filter(x => now - x < windowMs);
    fresh.push(now);
    hits.set(ip, fresh);
    if (fresh.length > max) return res.status(429).json({ error: "rate limit" });
    next();
  };
}

// --- Unified API handler ---
async function handleAction(payload, user = null) {
  try {
    switch (payload.action) {
      case "register": {
        if (typeof payload.username !== "string" || typeof payload.password !== "string")
          return { success: false, error: "bad input" };
        const ok = await registerUser(payload.username.trim(), payload.password.trim());
        return ok ? { success: true } : { success: false, error: "user exists" };
      }
      case "login": {
        const u = await authenticate(payload.username, payload.password);
        if (!u) return { success: false, error: "login failed" };
        const token = genToken();
        await saveToken(payload.username, token, Date.now() + config.security.tokenTTL);
        return { success: true, token };
      }
      case "sendMessage": {
        if (!user) return { success: false, error: "not auth" };
        if (typeof payload.channel !== "string" || typeof payload.text !== "string")
          return { success: false, error: "bad input" };
        const msg = await saveMessage({
          from: user,
          channel: payload.channel.trim(),
          text: payload.text.slice(0, config.security.maxMessageLength),
          ts: Date.now()
        });
        // Broadcast to WS
        for (const ws of wsClients) {
          if (ws.readyState === 1) {
            try { ws.send(JSON.stringify({ type: "message", msg })); } catch {}
          }
        }
        // Broadcast to SSE
        for (const res of sseClients) {
          try { res.write(`data: ${JSON.stringify({ type: "message", msg })}\n\n`); } catch {}
        }
        return { success: true, message: msg };
      }
      case "getMessages": {
        if (!user) return { success: false, error: "not auth" };
        const limit = Math.min(Math.max(parseInt(payload.limit || "100", 10), 1), 500);
        const before = payload.before ? parseInt(payload.before, 10) : null;
        const messages = await getMessages(payload.channel, limit, before);
        return { success: true, messages };
      }
      default:
        return { success: false, error: "unknown action" };
    }
  } catch (e) {
    return { success: false, error: "server error" };
  }
}

// --- HTTP unified endpoint ---
app.post("/api/unified", limiter(), async (req, res) => {
  const token = req.headers.authorization?.split(" ")[1] || null;
  const user = token ? await validateToken(token) : null;
  const response = await handleAction(req.body, user);
  res.json(response);
});

// --- Old HTTP routes kept for compatibility ---
app.post("/api/register", limiter(), async (req, res) => {
  const response = await handleAction({ action: "register", ...req.body });
  res.json(response);
});

app.post("/api/login", limiter(), async (req, res) => {
  const response = await handleAction({ action: "login", ...req.body });
  res.json(response);
});

app.post("/api/message", authMiddleware, async (req, res) => {
  const response = await handleAction({ action: "sendMessage", ...req.body }, req.user);
  res.json(response);
});

app.get("/api/messages", authMiddleware, async (req, res) => {
  const response = await handleAction({
    action: "getMessages",
    channel: req.query.channel,
    limit: req.query.limit,
    before: req.query.before
  }, req.user);
  res.json(response);
});

if (config.features.uploads) {
  app.post("/api/upload/avatar", authMiddleware, upload.single("avatar"), (req, res) => {
    if (!req.file) return res.status(400).json({ error: "invalid file" });
    res.json({ success: true, file: req.file.filename });
  });
}

// --- SSE endpoint ---
if (config.features.sse) {
  app.get("/sse", async (req, res) => {
    const token = req.query.token;
    if (!token) return res.status(401).end();
    const user = await validateToken(token);
    if (!user) return res.status(401).end();
    res.writeHead(200, {
      "Content-Type": "text/event-stream",
      "Cache-Control": "no-cache",
      Connection: "keep-alive"
    });
    sseClients.add(res);
    req.on("close", () => sseClients.delete(res));
  });
}

let server;
if (config.features.ws) {
  const wss = new WebSocketServer({ noServer: true });
  wss.on("connection", ws => {
    wsClients.add(ws);
    ws.isAlive = true;
    ws.on("pong", () => { ws.isAlive = true; });
    ws.on("close", () => wsClients.delete(ws));
    ws.on("message", async data => {
      try {
        const payload = JSON.parse(data.toString());
        const response = await handleAction(payload, ws.user);
        ws.send(JSON.stringify(response));
      } catch {}
    });
  });

  server = app.listen(config.server.port, config.server.host, () => {});
  const interval = setInterval(() => {
    for (const ws of wsClients) {
      if (ws.isAlive === false) { try { ws.terminate(); } catch {} continue; }
      ws.isAlive = false;
      try { ws.ping(); } catch {}
    }
  }, 30000);

  server.on("close", () => clearInterval(interval));

  server.on("upgrade", async (req, socket, head) => {
    try {
      const u = new URL(req.url, `http://${req.headers.host}`);
      if (u.pathname !== "/ws") return socket.destroy();
      const token = u.searchParams.get("token");
      if (!token) return socket.destroy();
      const user = await validateToken(token);
      if (!user) return socket.destroy();
      wss.handleUpgrade(req, socket, head, ws => {
        ws.user = user;
        wss.emit("connection", ws, req);
      });
    } catch {
      socket.destroy();
    }
  });
} else {
  server = app.listen(config.server.port, config.server.host, () => {});
}
