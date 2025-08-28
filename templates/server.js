import express from "express";
import cors from "cors";
import multer from "multer";
import { WebSocketServer } from "ws";
import crypto from "crypto";
import fs from "fs";
import path from "path";
import config from "./config.js";
import * as storage from "./storage/storage.js";

const app = express();
app.use(cors({ origin: config.cors.origin }));
app.use(express.json({ limit: "1mb" }));

const logger = {
    info: (message, meta = {}) => console.log(JSON.stringify({ level: "INFO", message, timestamp: new Date().toISOString(), ...meta })),
    warn: (message, meta = {}) => console.warn(JSON.stringify({ level: "WARN", message, timestamp: new Date().toISOString(), ...meta })),
    error: (message, meta = {}) => console.error(JSON.stringify({ level: "ERROR", message, timestamp: new Date().toISOString(), ...meta }))
};

if (config.features.uploads && !fs.existsSync(config.uploads.dir)) {
    fs.mkdirSync(config.uploads.dir, { recursive: true });
    logger.info("Uploads directory created", { path: config.uploads.dir });
}

const createUploader = (isAvatar = false) => multer({
    storage: multer.diskStorage({
        destination: config.uploads.dir,
        filename: (req, file, cb) => {
            const uniqueName = crypto.randomBytes(16).toString('hex');
            const extension = path.extname(file.originalname);
            cb(null, isAvatar ? `avatar_${uniqueName}${extension}` : `${uniqueName}${extension}`);
        }
    }),
    limits: { fileSize: config.uploads.maxFileSize },
    fileFilter: (req, file, cb) => {
        if (isAvatar && !config.uploads.allowedMime.includes(file.mimetype)) {
            cb(new Error('File type not allowed'), false);
        } else {
            cb(null, true);
        }
    }
});

const avatarUpload = createUploader(true);
const fileUpload = createUploader(false);

const wsClients = new Set();
const sseClients = new Set();

const genToken = () => crypto.randomBytes(32).toString("hex");

const authMiddleware = async (req, res, next) => {
    const auth = req.headers.authorization?.split(" ") || [];
    if (auth.length !== 2 || auth[0] !== "Bearer") {
        logger.warn("Authentication failed: no bearer token", { ip: req.ip });
        return res.status(401).json({ error: "no auth" });
    }

    const user = await storage.validateToken(auth[1]);
    if (!user) {
        logger.warn("Authentication failed: invalid token", { ip: req.ip });
        return res.status(401).json({ error: "invalid token" });
    }

    req.user = user;
    logger.info("User authenticated", { username: user, ip: req.ip });
    next();
};

const channelAuthMiddleware = async (req, res, next) => {
    await authMiddleware(req, res, async () => {
        const channel = req.body?.channel || req.query?.channel;
        if (channel && !await storage.isChannelMember(channel, req.user)) {
            logger.warn("Channel access denied", { username: req.user, channel, ip: req.ip });
            return res.status(403).json({ error: "not a channel member" });
        }
        next();
    });
};

const limiter = () => {
    const hits = new Map();
    return (req, res, next) => {
        const now = Date.now();
        const ip = req.ip || "unknown";
        const fresh = (hits.get(ip) || []).filter(x => now - x < config.rateLimit.windowMs);
        fresh.push(now);
        hits.set(ip, fresh);

        if (fresh.length > config.rateLimit.max) {
            logger.warn("Rate limit exceeded", { ip, hits: fresh.length });
            return res.status(429).json({ error: "rate limit" });
        }
        next();
    };
};

const actionHandlers = {
    register: async ({ username, password }, user) => {
        if (typeof username !== "string" || typeof password !== "string") {
            logger.warn("Register failed: bad input", { username: username?.substring(0, 10) });
            return { error: "bad input" };
        }
        const result = await storage.registerUser(username.trim(), password.trim());
        if (result) {
            logger.info("User registered successfully", { username: username.trim() });
            return { success: true };
        } else {
            logger.warn("Register failed: user exists", { username: username.trim() });
            return { error: "user exists" };
        }
    },

    login: async ({ username, password }, user) => {
        const u = await storage.authenticate(username, password);
        if (!u) {
            logger.warn("Login failed: invalid credentials", { username });
            return { error: "login failed" };
        }

        const token = genToken();
        await storage.saveToken(username, token, Date.now() + config.security.tokenTTL);
        logger.info("User logged in successfully", { username });
        return { success: true, token };
    },

    sendMessage: async ({ channel, text, replyTo }, user) => {
        if (!user || typeof channel !== "string" || typeof text !== "string") {
            logger.warn("Send message failed: bad input", { user, channel, textLength: text?.length });
            return { error: "bad input" };
        }
        if (!await storage.isChannelMember(channel, user)) {
            logger.warn("Send message failed: not channel member", { user, channel });
            return { error: "not a channel member" };
        }

        const msg = await storage.saveMessage({
            from: user,
            channel: channel.trim(),
            text: text.slice(0, config.security.maxMessageLength),
            ts: Date.now(),
            replyTo: replyTo || null
        });

        const messageData = JSON.stringify({ type: "message", msg });
        [...wsClients].filter(ws => ws.readyState === 1).forEach(ws => {
            try { ws.send(messageData); } catch {}
        });
        [...sseClients].forEach(res => {
            try { res.write(`data: ${messageData}\n\n`); } catch {}
        });

        logger.info("Message sent", { user, channel, messageId: msg.id });
        return { success: true, message: msg };
    },

    getMessages: async ({ channel, limit = 100, before }, user) => {
        if (!user || !await storage.isChannelMember(channel, user)) {
            logger.warn("Get messages failed: not authorized or not member", { user, channel });
            return { error: "not auth or not member" };
        }

        const messages = await storage.getMessages(
            channel,
            Math.min(Math.max(parseInt(limit), 1), 500),
            before ? parseInt(before) : null
        );

        logger.info("Messages retrieved", { user, channel, count: messages.length });
        return { success: true, messages };
    },

    createChannel: async ({ channelName }, user) => {
        if (!user || typeof channelName !== "string" || channelName.trim().length < 2) {
            logger.warn("Create channel failed: invalid channel name", { user, channelName });
            return { error: "invalid channel name" };
        }

        const result = await storage.createChannel(channelName.trim(), user);
        if (result) {
            logger.info("Channel created", { user, channel: channelName.trim() });
            return { success: true, channel: channelName.trim() };
        } else {
            logger.warn("Create channel failed: channel exists", { user, channel: channelName.trim() });
            return { error: "channel exists" };
        }
    },

    getChannels: async (payload, user) => {
        if (!user) {
            logger.warn("Get channels failed: not authenticated");
            return { error: "not auth" };
        }
        const channels = await storage.getChannels(user);
        logger.info("Channels retrieved", { user, count: channels.length });
        return { success: true, channels };
    },

    joinChannel: async ({ channel }, user) => {
        if (!user || typeof channel !== "string") {
            logger.warn("Join channel failed: invalid channel", { user, channel });
            return { error: "invalid channel" };
        }

        const result = await storage.joinChannel(channel, user);
        if (result) {
            logger.info("User joined channel", { user, channel });
            return { success: true };
        } else {
            logger.warn("Join channel failed: channel not found", { user, channel });
            return { error: "channel not found" };
        }
    },

    leaveChannel: async ({ channel }, user) => {
        if (!user || typeof channel !== "string") {
            logger.warn("Leave channel failed: invalid channel", { user, channel });
            return { error: "invalid channel" };
        }

        const result = await storage.leaveChannel(channel, user);
        if (result) {
            logger.info("User left channel", { user, channel });
            return { success: true };
        } else {
            logger.warn("Leave channel failed: not a member", { user, channel });
            return { error: "not a member" };
        }
    },

    getChannelMembers: async ({ channel }, user) => {
        if (!user || typeof channel !== "string") {
            logger.warn("Get channel members failed: invalid channel", { user, channel });
            return { error: "invalid channel" };
        }
        if (!await storage.isChannelMember(channel, user)) {
            logger.warn("Get channel members failed: not a member", { user, channel });
            return { error: "not a channel member" };
        }
        const members = await storage.getChannelMembers(channel);
        logger.info("Channel members retrieved", { user, channel, count: members.length });
        return { success: true, members };
    },

    "webrtc-offer": async ({ targetUser, offer, channel }, user) => {
        if (!user || !targetUser || !offer) {
            logger.warn("WebRTC offer failed: missing data", { user, targetUser });
            return { error: "missing offer data" };
        }
        await storage.saveWebRTCOffer(user, targetUser, offer, channel);

        const offerData = JSON.stringify({
            type: "webrtc-offer",
            from: user,
            offer: offer,
            channel: channel
        });

        [...wsClients].filter(ws => ws.user === targetUser && ws.readyState === 1)
            .forEach(ws => { try { ws.send(offerData); } catch {} });

        logger.info("WebRTC offer sent", { from: user, to: targetUser, channel });
        return { success: true };
    },

    "webrtc-answer": async ({ targetUser, answer }, user) => {
        if (!user || !targetUser || !answer) {
            logger.warn("WebRTC answer failed: missing data", { user, targetUser });
            return { error: "missing answer data" };
        }
        await storage.saveWebRTCAnswer(user, targetUser, answer);

        const answerData = JSON.stringify({
            type: "webrtc-answer",
            from: user,
            answer: answer
        });

        [...wsClients].filter(ws => ws.user === targetUser && ws.readyState === 1)
            .forEach(ws => { try { ws.send(answerData); } catch {} });

        logger.info("WebRTC answer sent", { from: user, to: targetUser });
        return { success: true };
    },

    "webrtc-ice-candidate": async ({ targetUser, candidate }, user) => {
        if (!user || !targetUser || !candidate) {
            logger.warn("WebRTC ICE candidate failed: missing data", { user, targetUser });
            return { error: "missing candidate data" };
        }
        await storage.saveICECandidate(user, targetUser, candidate);

        const candidateData = JSON.stringify({
            type: "webrtc-ice-candidate",
            from: user,
            candidate: candidate
        });

        [...wsClients].filter(ws => ws.user === targetUser && ws.readyState === 1)
            .forEach(ws => { try { ws.send(candidateData); } catch {} });

        logger.info("WebRTC ICE candidate sent", { from: user, to: targetUser });
        return { success: true };
    },

    "webrtc-get-offer": async ({ fromUser }, user) => {
        if (!user || !fromUser) {
            logger.warn("WebRTC get offer failed: missing fromUser", { user, fromUser });
            return { error: "missing fromUser" };
        }
        const offer = await storage.getWebRTCOffer(fromUser, user);
        logger.info("WebRTC offer retrieved", { user, fromUser });
        return { success: true, offer };
    },

    "webrtc-get-answer": async ({ fromUser }, user) => {
        if (!user || !fromUser) {
            logger.warn("WebRTC get answer failed: missing fromUser", { user, fromUser });
            return { error: "missing fromUser" };
        }
        const answer = await storage.getWebRTCAnswer(fromUser, user);
        logger.info("WebRTC answer retrieved", { user, fromUser });
        return { success: true, answer };
    },

    "webrtc-get-ice-candidates": async ({ fromUser }, user) => {
        if (!user || !fromUser) {
            logger.warn("WebRTC get ICE candidates failed: missing fromUser", { user, fromUser });
            return { error: "missing fromUser" };
        }
        const candidates = await storage.getICECandidates(fromUser, user);
        logger.info("WebRTC ICE candidates retrieved", { user, fromUser, count: candidates.length });
        return { success: true, candidates };
    },

    "webrtc-end-call": async ({ targetUser }, user) => {
        if (!user || !targetUser) {
            logger.warn("WebRTC end call failed: missing targetUser", { user, targetUser });
            return { error: "missing targetUser" };
        }
        const endCallData = JSON.stringify({ type: "webrtc-end-call", from: user });

        [...wsClients].filter(ws => ws.user === targetUser && ws.readyState === 1)
            .forEach(ws => { try { ws.send(endCallData); } catch {} });

        logger.info("WebRTC call ended", { from: user, to: targetUser });
        return { success: true };
    }
};

app.post("/api/unified", limiter(), async (req, res) => {
    const startTime = Date.now();
    try {
        const token = req.headers.authorization?.split(" ")[1];
        const user = token ? await storage.validateToken(token) : null;
        const handler = actionHandlers[req.body.action];

        if (!handler) {
            logger.warn("Unknown action requested", { action: req.body.action, ip: req.ip });
            return res.json({ success: false, error: "unknown action" });
        }

        const result = await handler(req.body, user);
        logger.info("Unified API request processed", {
            action: req.body.action,
            user: user,
            success: result.success,
            duration: Date.now() - startTime
        });
        res.json(result.success ? result : { success: false, ...result });
    } catch (e) {
        logger.error("Unified API error", { error: e.message, stack: e.stack, ip: req.ip });
        res.json({ success: false, error: "server error" });
    }
});

const createEndpoint = (method, path, middleware, action, paramMap = null) => {
    app[method](path, middleware, async (req, res) => {
        const startTime = Date.now();
        try {
            const params = paramMap ? paramMap(req) : req.method === 'GET' ? req.query : req.body;
            const result = await actionHandlers[action](params, req.user);
            logger.info("Endpoint request processed", {
                method,
                path,
                action,
                user: req.user,
                success: result.success,
                duration: Date.now() - startTime
            });
            res.json(result.success ? result : { success: false, ...result });
        } catch (e) {
            logger.error("Endpoint error", {
                method,
                path,
                action,
                error: e.message,
                stack: e.stack,
                ip: req.ip
            });
            res.json({ success: false, error: "server error" });
        }
    });
};

createEndpoint('post', '/api/register', limiter(), 'register');
createEndpoint('post', '/api/login', limiter(), 'login');
createEndpoint('post', '/api/message', channelAuthMiddleware, 'sendMessage');
createEndpoint('get', '/api/messages', channelAuthMiddleware, 'getMessages', req => req.query);
createEndpoint('post', '/api/channels/create', authMiddleware, 'createChannel');
createEndpoint('get', '/api/channels', authMiddleware, 'getChannels');
createEndpoint('post', '/api/channels/join', authMiddleware, 'joinChannel');
createEndpoint('post', '/api/channels/leave', authMiddleware, 'leaveChannel');
createEndpoint('get', '/api/channels/members', channelAuthMiddleware, 'getChannelMembers', req => req.query);
createEndpoint('post', '/api/webrtc/offer', authMiddleware, 'webrtc-offer');
createEndpoint('post', '/api/webrtc/answer', authMiddleware, 'webrtc-answer');
createEndpoint('post', '/api/webrtc/ice-candidate', authMiddleware, 'webrtc-ice-candidate');
createEndpoint('get', '/api/webrtc/offer', authMiddleware, 'webrtc-get-offer', req => req.query);
createEndpoint('get', '/api/webrtc/answer', authMiddleware, 'webrtc-get-answer', req => req.query);
createEndpoint('get', '/api/webrtc/ice-candidates', authMiddleware, 'webrtc-get-ice-candidates', req => req.query);
createEndpoint('post', '/api/webrtc/end-call', authMiddleware, 'webrtc-end-call');

app.post("/api/upload/avatar", authMiddleware, avatarUpload.single("avatar"), async (req, res) => {
    if (!req.file) {
        logger.warn("Avatar upload failed: no file", { user: req.user });
        return res.status(400).json({ error: "invalid file" });
    }

    const success = await storage.updateUserAvatar(req.user, req.file.filename);
    if (!success) {
        logger.error("Avatar upload failed: storage update failed", { user: req.user, filename: req.file.filename });
        return res.status(500).json({ error: "failed to update avatar" });
    }

    const extension = path.extname(req.file.filename).toLowerCase();
    let mimeType = 'image/jpeg';
    if (extension === '.png') mimeType = 'image/png';
    else if (extension === '.gif') mimeType = 'image/gif';
    else if (extension === '.webp') mimeType = 'image/webp';

    logger.info("Avatar uploaded successfully", { user: req.user, filename: req.file.filename });
    res.json({
        success: true,
        file: req.file.filename,
        avatarUrl: `/api/user/${req.user}/avatar`,
        mimeType: mimeType
    });
});

app.get("/api/user/:username/avatar", async (req, res) => {
    try {
        const users = await storage.getUsers();
        const user = users.find(u => u.username === req.params.username);

        if (!user?.avatar) {
            logger.warn("Avatar not found", { username: req.params.username });
            return res.status(404).json({ error: "avatar not found" });
        }

        if (!fs.existsSync(path.join(config.uploads.dir, user.avatar))) {
            logger.warn("Avatar file not found", { username: req.params.username, avatar: user.avatar });
            return res.status(404).json({ error: "avatar file not found" });
        }

        logger.info("Avatar served", { username: req.params.username });
        res.sendFile(user.avatar, { root: config.uploads.dir });
    } catch (error) {
        logger.error("Avatar serve error", { error: error.message, username: req.params.username });
        res.status(500).json({ error: "server error" });
    }
});

app.post("/api/upload/file", authMiddleware, fileUpload.single("file"), (req, res) => {
    if (!req.file) {
        logger.warn("File upload failed: no file", { user: req.user });
        return res.status(400).json({ error: "invalid file" });
    }

    logger.info("File uploaded successfully", {
        user: req.user,
        filename: req.file.filename,
        originalName: req.file.originalname,
        size: req.file.size
    });

    res.json({
        success: true,
        file: {
            filename: req.file.filename,
            originalName: req.file.originalname,
            mimetype: req.file.mimetype,
            size: req.file.size,
            uploadedAt: Date.now(),
            uploadedBy: req.user,
            downloadUrl: `/api/download/${req.file.filename}`
        }
    });
});

app.get("/api/download/:filename", (req, res) => {
    const filename = req.params.filename;
    const filePath = path.join(config.uploads.dir, filename);

    if (filename.includes('..') || filename.includes('/') || filename.includes('\\')) {
        logger.warn("Invalid filename attempted", { filename, ip: req.ip });
        return res.status(400).json({ error: "invalid filename" });
    }

    if (fs.existsSync(filePath)) {
        logger.info("File downloaded", { filename, ip: req.ip });
        res.download(filePath);
    } else {
        logger.warn("File not found for download", { filename, ip: req.ip });
        res.status(404).json({ error: "file not found" });
    }
});

if (config.features.ws) {
    const wss = new WebSocketServer({ noServer: true });

    wss.on("connection", (ws, req) => {
        wsClients.add(ws);
        ws.isAlive = true;

        logger.info("WebSocket connection established", { user: ws.user });

        ws.on("pong", () => { ws.isAlive = true; });
        ws.on("close", () => {
            wsClients.delete(ws);
            logger.info("WebSocket connection closed", { user: ws.user });
        });

        ws.on("message", async data => {
            try {
                const payload = JSON.parse(data.toString());
                const result = await actionHandlers[payload.action]?.(payload, ws.user);
                if (result) ws.send(JSON.stringify(result));
                logger.info("WebSocket message processed", { user: ws.user, action: payload.action });
            } catch (e) {
                logger.error("WebSocket error", { user: ws.user, error: e.message });
            }
        });
    });

    const server = app.listen(config.server.port, config.server.host, () => {
        logger.info("Server started", { host: config.server.host, port: config.server.port });
    });

    const interval = setInterval(() => {
        [...wsClients].forEach(ws => {
            if (!ws.isAlive) {
                ws.terminate();
                logger.info("WebSocket connection terminated due to inactivity", { user: ws.user });
                return;
            }
            ws.isAlive = false;
            try { ws.ping(); } catch {}
        });
    }, 30000);

    server.on("upgrade", async (req, socket, head) => {
        try {
            const url = new URL(req.url, `http://${req.headers.host}`);
            if (url.pathname !== "/ws") {
                logger.warn("WebSocket upgrade failed: invalid path", { path: url.pathname, ip: req.socket.remoteAddress });
                return socket.destroy();
            }

            const token = url.searchParams.get("token");
            const user = token ? await storage.validateToken(token) : null;
            if (!user) {
                logger.warn("WebSocket upgrade failed: invalid token", { ip: req.socket.remoteAddress });
                return socket.destroy();
            }

            wss.handleUpgrade(req, socket, head, ws => {
                ws.user = user;
                wss.emit("connection", ws, req);
            });
        } catch (error) {
            logger.error("WebSocket upgrade error", { error: error.message, ip: req.socket.remoteAddress });
            socket.destroy();
        }
    });

    server.on("close", () => {
        clearInterval(interval);
        logger.info("Server stopped");
    });
} else {
    app.listen(config.server.port, config.server.host, () => {
        logger.info("Server started", { host: config.server.host, port: config.server.port });
    });
}
