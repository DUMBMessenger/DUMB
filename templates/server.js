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
        
        logger.info("2FA login verified successfully", { username });
        return { 
            success: true, 
            token, 
            twoFactorEnabled: true,
            message: "Two-factor authentication successful" 
        };
    },

    setupTwoFactor: async (payload, user) => {
        if (!user) {
            logger.warn("2FA setup failed: not authenticated");
            return { error: "not auth" };
        }

        const secret = speakeasy.generateSecret({
            name: `ChatApp:${user}`,
            issuer: "ChatApp"
        });

        await storage.setTwoFactorSecret(user, secret.base32);
        
        const qrCodeUrl = await QRCode.toDataURL(secret.otpauth_url);
        
        logger.info("2FA setup initiated", { user });
        return { success: true, secret: secret.base32, qrCodeUrl };
    },

    verifyTwoFactor: async ({ token }, user) => {
        if (!user) {
            logger.warn("2FA verification failed: not authenticated");
            return { error: "not auth" };
        }

        const secret = await storage.getTwoFactorSecret(user);
        const verified = speakeasy.totp.verify({
            secret: secret,
            encoding: 'base32',
            token: token,
            window: 1
        });

        if (verified) {
            await storage.enableTwoFactor(user, true);
            logger.info("2FA enabled successfully", { user });
            return { success: true };
        } else {
            logger.warn("2FA verification failed", { user });
            return { error: "invalid token" };
        }
    },

    disableTwoFactor: async ({ password }, user) => {
        if (!user) {
            logger.warn("2FA disable failed: not authenticated");
            return { error: "not auth" };
        }

        const authenticated = await storage.authenticate(user, password);
        if (!authenticated) {
            logger.warn("2FA disable failed: invalid password", { user });
            return { error: "invalid password" };
        }

        await storage.enableTwoFactor(user, false);
        await storage.setTwoFactorSecret(user, null);
        
        logger.info("2FA disabled successfully", { user });
        return { success: true };
    },

    checkUpdates: async (payload, user) => {
        if (!user) {
            logger.warn("Update check failed: not authenticated");
            return { error: "not auth" };
        }

        const updateInfo = await checkGitHubUpdates();
        
        if (updateInfo) {
            logger.info("Update check completed", { user, hasUpdates: true });
            return { 
                success: true, 
                hasUpdates: true, 
                updateInfo 
            };
        } else {
            logger.info("Update check completed", { user, hasUpdates: false });
            return { 
                success: true, 
                hasUpdates: false 
            };
        }
    },

    sendMessage: async ({ channel, text, replyTo, fileId, voiceMessage }, user) => {
        if (!user || typeof channel !== "string" || typeof text !== "string") {
            logger.warn("Send message failed: bad input", { user, channel, textLength: text?.length });
            return { error: "bad input" };
        }
        if (!await storage.isChannelMember(channel, user)) {
            logger.warn("Send message failed: not channel member", { user, channel });
            return { error: "not a channel member" };
        }

        let fileAttachment = null;
        if (fileId) {
            fileAttachment = {
                filename: fileId,
                originalName: fileId,
                mimetype: "application/octet-stream", 
                size: 0,
                downloadUrl: `/api/download/${fileId}`
            };
        }

        let voiceAttachment = null;
        if (voiceMessage) {
            voiceAttachment = {
                filename: voiceMessage,
                duration: 0,
                downloadUrl: `/api/download/${voiceMessage}`
            };
        }

        const msg = await storage.saveMessage({
            from: user,
            channel: channel.trim(),
            text: text.slice(0, config.security.maxMessageLength),
            ts: Date.now(),
            replyTo: replyTo || null,
            file: fileAttachment,
            voice: voiceAttachment
        });

        const messageData = JSON.stringify({ type: "message", msg });
        [...wsClients].filter(ws => ws.readyState === 1).forEach(ws => {
            try { ws.send(messageData); } catch {}
        });
        [...sseClients].forEach(res => {
            try { res.write(`data: ${messageData}\n\n`); } catch {}
        });

        logger.info("Message sent", { user, channel, messageId: msg.id, hasFile: !!fileId, hasVoice: !!voiceMessage });
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
    },

    uploadVoiceMessage: async ({ channel, duration }, user) => {
        if (!user || !channel) {
            logger.warn("Voice message upload failed: missing parameters", { user, channel });
            return { error: "missing parameters" };
        }

        const voiceId = crypto.randomBytes(16).toString("hex") + ".ogg";
        logger.info("Voice message upload initiated", { user, channel, voiceId, duration });
        return { success: true, voiceId, uploadUrl: `/api/upload/voice/${voiceId}` };
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
createEndpoint('post', '/api/2fa/verify-login', limiter(), 'verify2FALogin');
createEndpoint('post', '/api/2fa/setup', require2FAMiddleware, 'setupTwoFactor');
createEndpoint('post', '/api/2fa/verify', require2FAMiddleware, 'verifyTwoFactor');
createEndpoint('post', '/api/2fa/disable', require2FAMiddleware, 'disableTwoFactor');
createEndpoint('get', '/api/updates/check', require2FAMiddleware, 'checkUpdates');
createEndpoint('post', '/api/message', channelAuthMiddleware, 'sendMessage');
createEndpoint('get', '/api/messages', channelAuthMiddleware, 'getMessages', req => req.query);
createEndpoint('post', '/api/channels/create', require2FAMiddleware, 'createChannel');
createEndpoint('get', '/api/channels', require2FAMiddleware, 'getChannels');
createEndpoint('post', '/api/channels/join', require2FAMiddleware, 'joinChannel');
createEndpoint('post', '/api/channels/leave', require2FAMiddleware, 'leaveChannel');
createEndpoint('get', '/api/channels/members', channelAuthMiddleware, 'getChannelMembers', req => req.query);
createEndpoint('post', '/api/webrtc/offer', require2FAMiddleware, 'webrtc-offer');
createEndpoint('post', '/api/webrtc/answer', require2FAMiddleware, 'webrtc-answer');
createEndpoint('post', '/api/webrtc/ice-candidate', require2FAMiddleware, 'webrtc-ice-candidate');
createEndpoint('get', '/api/webrtc/offer', require2FAMiddleware, 'webrtc-get-offer', req => req.query);
createEndpoint('get', '/api/webrtc/answer', require2FAMiddleware, 'webrtc-get-answer', req => req.query);
createEndpoint('get', '/api/webrtc/ice-candidates', require2FAMiddleware, 'webrtc-get-ice-candidates', req => req.query);
createEndpoint('post', '/api/webrtc/end-call', require2FAMiddleware, 'webrtc-end-call');
createEndpoint('post', '/api/voice/upload', require2FAMiddleware, 'uploadVoiceMessage');

app.post("/api/upload/avatar", require2FAMiddleware, avatarUpload.single("avatar"), async (req, res) => {
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

app.post("/api/upload/file", require2FAMiddleware, fileUpload.single("file"), (req, res) => {
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

app.post("/api/upload/voice/:voiceId", require2FAMiddleware, (req, res) => {
    const voiceId = req.params.voiceId;
    const filePath = path.join(config.uploads.dir, voiceId);
    
    const writeStream = fs.createWriteStream(filePath);
    req.pipe(writeStream);

    writeStream.on('finish', () => {
        logger.info("Voice message uploaded", { user: req.user, voiceId, size: fs.statSync(filePath).size });
        res.json({ success: true, voiceId });
    });

    writeStream.on('error', (error) => {
        logger.error("Voice message upload failed", { user: req.user, voiceId, error: error.message });
        res.status(500).json({ error: "upload failed" });
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
        logger.info("File download started", { filename, ip: req.ip, size: fs.statSync(filePath).size });
        res.download(filePath, (err) => {
            if (err) {
                logger.error("File download error", { filename, error: err.message, ip: req.ip });
            } else {
                logger.info("File download completed", { filename, ip: req.ip });
            }
        });
    } else {
        logger.warn("File not found for download", { filename, ip: req.ip });
        res.status(404).json({ error: "file not found" });
    }
});

setInterval(() => {
    const now = Date.now();
    for (const [username, session] of pending2FASessions.entries()) {
        if (now - session.createdAt > 5 * 60 * 1000) {
            pending2FASessions.delete(username);
            logger.info("Expired 2FA session cleaned up", { username });
        }
    }
}, 10 * 60 * 1000);

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

            const twoFactorEnabled = await storage.isTwoFactorEnabled(user);
            if (twoFactorEnabled) {
                const session = pending2FASessions.get(user);
                if (!session || !session.twoFactorVerified) {
                    logger.warn("WebSocket upgrade failed: 2FA required", { user, ip: req.socket.remoteAddress });
                    return socket.destroy();
                }
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
    })
}
