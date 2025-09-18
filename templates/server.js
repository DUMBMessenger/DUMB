import express from "express";
import cors from "cors";
import multer from "multer";
import { WebSocketServer } from "ws";
import crypto from "crypto";
import fs from "fs";
import path from "path";
import config from "./config.js";
import * as storage from "./storage/storage.js";
import speakeasy from "speakeasy";
import QRCode from "qrcode";
import https from "https";

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
            cb(null, file.originalname);
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

const pending2FASessions = new Map();

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

const require2FAMiddleware = async (req, res, next) => {
    await authMiddleware(req, res, async () => {
        const twoFactorEnabled = await storage.isTwoFactorEnabled(req.user);
        if (twoFactorEnabled) {
            const session = pending2FASessions.get(req.user);
            if (!session || !session.twoFactorVerified) {
                logger.warn("2FA verification required", { username: req.user, ip: req.ip });
                return res.status(403).json({ error: "2fa_required", message: "Two-factor authentication required" });
            }
        }
        next();
    });
};

const channelAuthMiddleware = async (req, res, next) => {
    await require2FAMiddleware(req, res, async () => {
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

const checkGitHubUpdates = async () => {
    if (!config.github?.owner || !config.github?.repo) {
        return null;
    }

    try {
        const options = {
            hostname: 'api.github.com',
            path: `/repos/${config.github.owner}/${config.github.repo}/commits?per_page=1`,
            method: 'GET',
            headers: {
                'User-Agent': 'ChatApp-Server',
                'Accept': 'application/vnd.github.v3+json'
            }
        };

        return new Promise((resolve, reject) => {
            const req = https.request(options, (res) => {
                let data = '';
                res.on('data', chunk => data += chunk);
                res.on('end', () => {
                    if (res.statusCode === 200) {
                        const commits = JSON.parse(data);
                        if (commits.length > 0) {
                            resolve({
                                latestCommit: commits[0].sha,
                                message: commits[0].commit.message,
                                date: commits[0].commit.committer.date,
                                url: commits[0].html_url
                            });
                        } else {
                            resolve(null);
                        }
                    } else {
                        resolve(null);
                    }
                });
            });

            req.on('error', (error) => {
                logger.error("GitHub API error", { error: error.message });
                resolve(null);
            });

            req.setTimeout(5000, () => {
                req.destroy();
                resolve(null);
            });

            req.end();
        });
    } catch (error) {
        logger.error("GitHub update check error", { error: error.message });
        return null;
    }
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

    login: async ({ username, password, twoFactorToken }, user) => {
        const u = await storage.authenticate(username, password);
        if (!u) {
            logger.warn("Login failed: invalid credentials", { username });
            return { error: "login failed" };
        }

        const twoFactorEnabled = await storage.isTwoFactorEnabled(username);
        
        if (twoFactorEnabled) {
            if (!twoFactorToken) {
                const sessionId = crypto.randomBytes(16).toString("hex");
                pending2FASessions.set(username, {
                    sessionId,
                    username,
                    twoFactorVerified: false,
                    createdAt: Date.now()
                });
                
                logger.info("2FA required for login", { username, sessionId });
                return { 
                    success: false, 
                    requires2FA: true,
                    sessionId,
                    message: "Two-factor authentication required" 
                };
            }

            const secret = await storage.getTwoFactorSecret(username);
            const verified = speakeasy.totp.verify({
                secret: secret,
                encoding: 'base32',
                token: twoFactorToken,
                window: 1
            });

            if (!verified) {
                logger.warn("2FA verification failed", { username });
                return { error: "invalid 2fa token" };
            }

            const session = pending2FASessions.get(username);
            if (session) {
                session.twoFactorVerified = true;
                pending2FASessions.set(username, session);
            }
        }

        const token = genToken();
        await storage.saveToken(username, token, Date.now() + config.security.tokenTTL);
        
        pending2FASessions.delete(username);
        
        logger.info("User logged in successfully", { username, twoFactorEnabled });
        return { success: true, token, twoFactorEnabled };
    },

    verify2FALogin: async ({ username, sessionId, twoFactorToken }, user) => {
        if (!username || !sessionId || !twoFactorToken) {
            logger.warn("2FA verification failed: missing parameters", { username });
            return { error: "missing parameters" };
        }

        const session = pending2FASessions.get(username);
        if (!session || session.sessionId !== sessionId) {
            logger.warn("2FA verification failed: invalid session", { username, sessionId });
            return { error: "invalid session" };
        }

        if (Date.now() - session.createdAt > 5 * 60 * 1000) {
            pending2FASessions.delete(username);
            logger.warn("2FA verification failed: session expired", { username });
            return { error: "session expired" };
        }

        const secret = await storage.getTwoFactorSecret(username);
        const verified = speakeasy.totp.verify({
            secret: secret,
            encoding: 'base32',
            token: twoFactorToken,
            window: 1
        });

        if (!verified) {
            logger.warn("2FA verification failed: invalid token", { username });
            return { error: "invalid 2fa token" };
        }

        session.twoFactorVerified = true;
        pending2FASessions.set(username, session);

        const token = genToken();
        await storage.saveToken(username, token, Date.now() + config.security.tokenTTL);
        
        logger.info("2FA verification successful", { username });
        return { success: true, token };
    },

    setup2FA: async (data, user) => {
        const secret = speakeasy.generateSecret({
            name: `ChatApp (${user})`,
            issuer: "ChatApp"
        });

        await storage.setTwoFactorSecret(user, secret.base32);
        
        const qrCodeUrl = await QRCode.toDataURL(secret.otpauth_url);
        
        logger.info("2FA setup initiated", { username: user });
        return { 
            success: true, 
            secret: secret.base32,
            qrCodeUrl,
            manualEntryCode: secret.otpauth_url 
        };
    },

    enable2FA: async ({ token }, user) => {
        const secret = await storage.getTwoFactorSecret(user);
        if (!secret) {
            logger.warn("2FA enable failed: no secret found", { username: user });
            return { error: "setup required" };
        }

        const verified = speakeasy.totp.verify({
            secret: secret,
            encoding: 'base32',
            token: token,
            window: 1
        });

        if (!verified) {
            logger.warn("2FA enable failed: invalid token", { username: user });
            return { error: "invalid token" };
        }

        await storage.enableTwoFactor(user, true);
        logger.info("2FA enabled successfully", { username: user });
        return { success: true };
    },

    disable2FA: async ({ token }, user) => {
        const secret = await storage.getTwoFactorSecret(user);
        if (!secret) {
            logger.warn("2FA disable failed: not enabled", { username: user });
            return { error: "not enabled" };
        }

        const verified = speakeasy.totp.verify({
            secret: secret,
            encoding: 'base32',
            token: token,
            window: 1
        });

        if (!verified) {
            logger.warn("2FA disable failed: invalid token", { username: user });
            return { error: "invalid token" };
        }

        await storage.enableTwoFactor(user, false);
        await storage.setTwoFactorSecret(user, null);
        logger.info("2FA disabled successfully", { username: user });
        return { success: true };
    },

    get2FAStatus: async (data, user) => {
        const enabled = await storage.isTwoFactorEnabled(user);
        return { enabled };
    },

    createChannel: async ({ name, customId }, user) => {
        if (!name || typeof name !== "string") {
            logger.warn("Channel creation failed: invalid name", { username: user });
            return { error: "invalid channel name" };
        }

        const channelId = await storage.createChannel(name.trim(), user, customId);
        if (!channelId) {
            logger.warn("Channel creation failed: already exists", { username: user, channelName: name });
            return { error: "channel exists" };
        }

        logger.info("Channel created successfully", { username: user, channelName: name, channelId });
        return { success: true, channelId };
    },

    getChannels: async (data, user) => {
        const channels = await storage.getChannels(user);
        logger.info("Channels retrieved", { username: user, count: channels.length });
        return { channels };
    },

    joinChannel: async ({ channel }, user) => {
        if (!channel) {
            logger.warn("Channel join failed: no channel specified", { username: user });
            return { error: "channel required" };
        }

        const result = await storage.joinChannel(channel, user);
        if (!result) {
            logger.warn("Channel join failed: invalid channel", { username: user, channel });
            return { error: "invalid channel" };
        }

        logger.info("User joined channel", { username: user, channel });
        return { success: true };
    },

    leaveChannel: async ({ channel }, user) => {
        if (!channel) {
            logger.warn("Channel leave failed: no channel specified", { username: user });
            return { error: "channel required" };
        }

        const result = await storage.leaveChannel(channel, user);
        if (!result) {
            logger.warn("Channel leave failed: not a member", { username: user, channel });
            return { error: "not a member" };
        }

        logger.info("User left channel", { username: user, channel });
        return { success: true };
    },

    getChannelMembers: async ({ channel }, user) => {
        if (!channel) {
            logger.warn("Channel members fetch failed: no channel specified", { username: user });
            return { error: "channel required" };
        }

        const members = await storage.getChannelMembers(channel);
        logger.info("Channel members retrieved", { username: user, channel, count: members.length });
        return { members };
    },

    getMessages: async ({ channel, limit = 50, before }, user) => {
        if (!channel) {
            logger.warn("Messages fetch failed: no channel specified", { username: user });
            return { error: "channel required" };
        }

        const messages = await storage.getMessages(channel, Math.min(limit, 100), before);
        logger.info("Messages retrieved", { username: user, channel, count: messages.length });
        return { messages };
    },

    sendMessage: async ({ channel, text, replyTo }, user) => {
        if (!channel || !text || typeof text !== "string") {
            logger.warn("Message send failed: invalid parameters", { username: user, channel });
            return { error: "bad input" };
        }

        const msg = {
            from: user,
            channel: channel,
            text: text.trim(),
            ts: Date.now(),
            replyTo: replyTo || null
        };

        const saved = await storage.saveMessage(msg);
        
        const messageToSend = {
            ...saved,
            type: "message",
            action: "new"
        };

        wsClients.forEach(client => {
            if (client.readyState === 1 && client.user === user) {
                client.send(JSON.stringify(messageToSend));
            }
        });

        sseClients.forEach(client => {
            if (client.user === user) {
                client.res.write(`data: ${JSON.stringify(messageToSend)}\n\n`);
            }
        });

        logger.info("Message sent", { username: user, channel, messageId: saved.id });
        return { success: true, message: saved };
    },

    getUsers: async (data, user) => {
        const users = await storage.getUsers();
        logger.info("Users list retrieved", { username: user, count: users.length });
        return { users };
    },

    uploadAvatar: async (req, user) => {
        if (!req.file) {
            logger.warn("Avatar upload failed: no file", { username: user });
            return { error: "no file" };
        }

        const result = await storage.updateUserAvatar(user, req.file.filename);
        if (!result) {
            logger.warn("Avatar upload failed: user not found", { username: user });
            return { error: "user not found" };
        }

        logger.info("Avatar uploaded successfully", { username: user, filename: req.file.filename });
        return { success: true, filename: req.file.filename };
    },

    uploadFile: async (req, user) => {
        if (!req.file) {
            logger.warn("File upload failed: no file", { username: user });
            return { error: "no file" };
        }

        const fileUrl = `${config.features.uploads ? config.uploads.urlBase : ''}/${req.file.filename}`;
        logger.info("File uploaded successfully", { username: user, filename: req.file.filename });
        return { success: true, filename: req.file.filename, url: fileUrl };
    },

    webrtcOffer: async ({ toUser, offer, channel }, user) => {
        await storage.saveWebRTCOffer(user, toUser, offer, channel);
        logger.info("WebRTC offer sent", { from: user, to: toUser, channel });
        return { success: true };
    },

    webrtcAnswer: async ({ toUser, answer }, user) => {
        await storage.saveWebRTCAnswer(user, toUser, answer);
        logger.info("WebRTC answer sent", { from: user, to: toUser });
        return { success: true };
    },

    iceCandidate: async ({ toUser, candidate }, user) => {
        await storage.saveICECandidate(user, toUser, candidate);
        logger.info("ICE candidate sent", { from: user, to: toUser });
        return { success: true };
    },

    getWebRTCOffer: async ({ fromUser }, user) => {
        const offer = await storage.getWebRTCOffer(fromUser, user);
        if (offer) {
            logger.info("WebRTC offer retrieved", { from: fromUser, to: user });
            return { success: true, offer: offer.offer, channel: offer.channel };
        }
        logger.info("No WebRTC offer found", { from: fromUser, to: user });
        return { success: false };
    },

    getWebRTCAnswer: async ({ fromUser }, user) => {
        const answer = await storage.getWebRTCAnswer(fromUser, user);
        if (answer) {
            logger.info("WebRTC answer retrieved", { from: fromUser, to: user });
            return { success: true, answer: answer.answer };
        }
        logger.info("No WebRTC answer found", { from: fromUser, to: user });
        return { success: false };
    },

    getICECandidates: async ({ fromUser }, user) => {
        const candidates = await storage.getICECandidates(fromUser, user);
        logger.info("ICE candidates retrieved", { from: fromUser, to: user, count: candidates.length });
        return { success: true, candidates };
    },

    getUpdates: async (data, user) => {
        const updateInfo = await checkGitHubUpdates();
        return { 
            success: true, 
            updateAvailable: !!updateInfo,
            updateInfo 
        };
    }
};

app.post("/api/:action", limiter(), async (req, res) => {
    const { action } = req.params;
    const handler = actionHandlers[action];

    if (!handler) {
        logger.warn("Unknown API action", { action, ip: req.ip });
        return res.status(404).json({ error: "unknown action" });
    }

    try {
        let result;
        if (action === "uploadAvatar" || action === "uploadFile") {
            const uploadMiddleware = action === "uploadAvatar" ? avatarUpload.single("file") : fileUpload.single("file");
            
            uploadMiddleware(req, res, async (err) => {
                if (err) {
                    logger.error("Upload error", { error: err.message, action, ip: req.ip });
                    return res.status(400).json({ error: "upload failed", details: err.message });
                }

                try {
                    if (action === "uploadAvatar") {
                        await authMiddleware(req, res, async () => {
                            result = await handler(req, req.user);
                            res.json(result);
                        });
                    } else {
                        await channelAuthMiddleware(req, res, async () => {
                            result = await handler(req, req.user);
                            res.json(result);
                        });
                    }
                } catch (error) {
                    logger.error("Handler error after upload", { error: error.message, action, ip: req.ip });
                    res.status(500).json({ error: "internal error" });
                }
            });
        } else {
            if (action === "register") {
                result = await handler(req.body);
                res.json(result);
            } else if (action === "login" || action === "verify2FALogin") {
                result = await handler(req.body);
                res.json(result);
            } else {
                await authMiddleware(req, res, async () => {
                    if (action === "setup2FA" || action === "enable2FA" || action === "disable2FA" || action === "get2FAStatus") {
                        result = await handler(req.body, req.user);
                    } else {
                        await require2FAMiddleware(req, res, async () => {
                            result = await handler(req.body, req.user);
                        });
                    }
                    res.json(result);
                });
            }
        }
    } catch (error) {
        logger.error("API handler error", { error: error.message, action, ip: req.ip });
        res.status(500).json({ error: "internal error" });
    }
});

app.get("/api/events", authMiddleware, async (req, res) => {
    res.setHeader("Content-Type", "text/event-stream");
    res.setHeader("Cache-Control", "no-cache");
    res.setHeader("Connection", "keep-alive");
    res.setHeader("Access-Control-Allow-Origin", config.cors.origin);
    res.flushHeaders();

    const client = { res, user: req.user, id: crypto.randomBytes(8).toString("hex") };
    sseClients.add(client);

    logger.info("SSE client connected", { username: req.user, clientId: client.id });

    req.on("close", () => {
        sseClients.delete(client);
        logger.info("SSE client disconnected", { username: req.user, clientId: client.id });
    });

    res.write(`data: ${JSON.stringify({ type: "connected", clientId: client.id })}\n\n`);
});

app.get("/uploads/:filename", (req, res) => {
    if (!config.features.uploads) {
        return res.status(403).json({ error: "uploads disabled" });
    }

    const filename = req.params.filename;
    const filePath = path.join(config.uploads.dir, filename);

    if (!fs.existsSync(filePath)) {
        return res.status(404).json({ error: "file not found" });
    }

    res.sendFile(filePath);
});

const server = app.listen(config.port, () => {
    logger.info("Server started", { port: config.port });
});

const wss = new WebSocketServer({ server, path: "/ws" });

wss.on("connection", async (ws, req) => {
    const url = new URL(req.url, `http://${req.headers.host}`);
    const token = url.searchParams.get("token");

    if (!token) {
        ws.close(1008, "No token");
        logger.warn("WebSocket connection rejected: no token", { ip: req.socket.remoteAddress });
        return;
    }

    const user = await storage.validateToken(token);
    if (!user) {
        ws.close(1008, "Invalid token");
        logger.warn("WebSocket connection rejected: invalid token", { ip: req.socket.remoteAddress });
        return;
    }

    ws.user = user;
    ws.id = crypto.randomBytes(8).toString("hex");
    wsClients.add(ws);

    logger.info("WebSocket client connected", { username: user, clientId: ws.id, ip: req.socket.remoteAddress });

    ws.on("message", async (data) => {
        try {
            const message = JSON.parse(data);
            const handler = actionHandlers[message.action];

            if (!handler) {
                logger.warn("Unknown WebSocket action", { action: message.action, username: user });
                ws.send(JSON.stringify({ error: "unknown action" }));
                return;
            }

            const result = await handler(message, user);
            ws.send(JSON.stringify({ ...result, action: message.action }));
        } catch (error) {
            logger.error("WebSocket message error", { error: error.message, username: user });
            ws.send(JSON.stringify({ error: "internal error" }));
        }
    });

    ws.on("close", () => {
        wsClients.delete(ws);
        logger.info("WebSocket client disconnected", { username: user, clientId: ws.id });
    });

    ws.send(JSON.stringify({ type: "connected", clientId: ws.id }));
});

process.on("uncaughtException", (error) => {
    logger.error("Uncaught exception", { error: error.message, stack: error.stack });
});

process.on("unhandledRejection", (reason, promise) => {
    logger.error("Unhandled rejection", { reason: reason?.message || reason, promise });
});

setInterval(() => {
    const now = Date.now();
    for (const [username, session] of pending2FASessions.entries()) {
        if (now - session.createdAt > 5 * 60 * 1000) {
            pending2FASessions.delete(username);
            logger.info("Pending 2FA session expired", { username });
        }
    }
}, 60000);
