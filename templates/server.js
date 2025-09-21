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
            const uniqueName = `${crypto.randomBytes(8).toString('hex')}_${file.originalname}`;
            cb(null, uniqueName);
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

    setup2FA: async (data, user) => {
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

    enable2FA: async ({ token }, user) => {
        if (!user) {
            logger.warn("2FA enable failed: not authenticated");
            return { error: "not auth" };
        }

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

    disable2FA: async ({ password }, user) => {
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

    get2FAStatus: async (data, user) => {
        if (!user) {
            logger.warn("2FA status check failed: not authenticated");
            return { error: "not auth" };
        }

        const enabled = await storage.isTwoFactorEnabled(user);
        return { success: true, enabled };
    },

    createChannel: async ({ name, customId }, user) => {
        if (!user || !name || typeof name !== "string" || name.trim().length < 2) {
            logger.warn("Channel creation failed: invalid name", { username: user, channelName: name });
            return { error: "invalid channel name" };
        }

        const channelId = await storage.createChannel(name.trim(), user, customId);
        if (!channelId) {
            logger.warn("Channel creation failed: already exists", { username: user, channelName: name });
            return { error: "channel exists" };
        }

        logger.info("Channel created successfully", { username: user, channelName: name, channelId });
        return { success: true, channelId, channel: name.trim() };
    },

    getChannels: async (data, user) => {
        if (!user) {
            logger.warn("Get channels failed: not authenticated");
            return { error: "not auth" };
        }

        const channels = await storage.getChannels(user);
        logger.info("Channels retrieved", { username: user, count: channels.length });
        return { success: true, channels };
    },

    searchChannels: async ({ query }, user) => {
    if (!user) {
        logger.warn("Search channels failed: not authenticated");
        return { error: "not auth" };
    }

    if (query === undefined || query === null) {
        logger.warn("Search channels failed: invalid query", { username: user, query });
        return { error: "invalid query" };
    }

    const channels = await storage.searchChannels(query);
    logger.info("Channels search completed", { username: user, query, count: channels.length });
    return { success: true, channels };
   },

    joinChannel: async ({ channel }, user) => {
        if (!user || !channel || typeof channel !== "string") {
            logger.warn("Channel join failed: invalid channel", { username: user, channel });
            return { error: "invalid channel" };
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
        if (!user || !channel || typeof channel !== "string") {
            logger.warn("Channel leave failed: invalid channel", { username: user, channel });
            return { error: "invalid channel" };
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
        if (!user || !channel || typeof channel !== "string") {
            logger.warn("Channel members fetch failed: invalid channel", { username: user, channel });
            return { error: "invalid channel" };
        }

        if (!await storage.isChannelMember(channel, user)) {
            logger.warn("Get channel members failed: not a member", { user, channel });
            return { error: "not a channel member" };
        }

        const members = await storage.getChannelMembers(channel);
        logger.info("Channel members retrieved", { username: user, channel, count: members.length });
        return { success: true, members };
    },

    getMessages: async ({ channel, limit = 50, before }, user) => {
        if (!user || !channel || typeof channel !== "string") {
            logger.warn("Messages fetch failed: invalid parameters", { username: user, channel });
            return { error: "invalid parameters" };
        }

        if (!await storage.isChannelMember(channel, user)) {
            logger.warn("Get messages failed: not channel member", { user, channel });
            return { error: "not a channel member" };
        }

        const messages = await storage.getMessages(channel, Math.min(limit, 100), before);
        
        for (let message of messages) {
            if (message.voice && message.voice.filename) {
                message.voice.duration = await storage.getVoiceMessageDuration(message.voice.filename) || 0;
            }
        }
        
        logger.info("Messages retrieved", { username: user, channel, count: messages.length });
        return { success: true, messages };
    },

    sendMessage: async ({ channel, text, replyTo, fileId, voiceMessage }, user) => {
        if (!user || !channel) {
            logger.warn("Message send failed: invalid parameters", { username: user, channel });
            return { error: "bad input" };
        }

        if (!text && !fileId && !voiceMessage) {
            logger.warn("Message send failed: no content", { username: user, channel });
            return { error: "no content" };
        }

        if (!await storage.isChannelMember(channel, user)) {
            logger.warn("Send message failed: not channel member", { user, channel });
            return { error: "not a channel member" };
        }

        let fileAttachment = null;
        if (fileId) {
            const fileInfo = await storage.getFileInfo(fileId);
            if (fileInfo) {
                fileAttachment = {
                    filename: fileInfo.filename,
                    originalName: fileInfo.originalName,
                    mimetype: fileInfo.mimetype,
                    size: fileInfo.size,
                    downloadUrl: `/api/download/${fileInfo.filename}`
                };
            }
        }

        let voiceAttachment = null;
        if (voiceMessage) {
            const duration = await storage.getVoiceMessageDuration(voiceMessage) || 0;
            voiceAttachment = {
                filename: voiceMessage,
                duration: duration,
                downloadUrl: `/api/download/${voiceMessage}`
            };
        }

        const msg = {
            from: user,
            channel: channel,
            text: text ? text.trim().slice(0, config.security.maxMessageLength || 1000) : "",
            ts: Date.now(),
            replyTo: replyTo || null,
            file: fileAttachment,
            voice: voiceAttachment
        };

        const saved = await storage.saveMessage(msg);
        
        const messageToSend = {
            ...saved,
            type: "message",
            action: "new"
        };

        wsClients.forEach(client => {
            if (client.readyState === 1) {
                client.send(JSON.stringify(messageToSend));
            }
        });

        sseClients.forEach(client => {
            client.res.write(`data: ${JSON.stringify(messageToSend)}\n\n`);
        });

        logger.info("Message sent", { username: user, channel, messageId: saved.id, hasFile: !!fileId, hasVoice: !!voiceMessage, hasText: !!text });
        return { success: true, message: saved };
    },

    sendVoiceOnly: async ({ channel, voiceMessage }, user) => {
        if (!user || !channel || !voiceMessage) {
            logger.warn("Voice only send failed: invalid parameters", { username: user, channel, voiceMessage });
            return { error: "bad input" };
        }

        if (!await storage.isChannelMember(channel, user)) {
            logger.warn("Send voice failed: not channel member", { user, channel });
            return { error: "not a channel member" };
        }

        const duration = await storage.getVoiceMessageDuration(voiceMessage) || 0;

        const voiceAttachment = {
            filename: voiceMessage,
            duration: duration,
            downloadUrl: `/api/download/${voiceMessage}`
        };

        const msg = {
            from: user,
            channel: channel,
            text: "",
            ts: Date.now(),
            replyTo: null,
            file: null,
            voice: voiceAttachment
        };

        const saved = await storage.saveMessage(msg);
        
        const messageToSend = {
            ...saved,
            type: "message",
            action: "new"
        };

        wsClients.forEach(client => {
            if (client.readyState === 1) {
                client.send(JSON.stringify(messageToSend));
            }
        });

        sseClients.forEach(client => {
            client.res.write(`data: ${JSON.stringify(messageToSend)}\n\n`);
        });

        logger.info("Voice message sent", { username: user, channel, messageId: saved.id, voiceMessage, duration });
        return { success: true, message: saved };
    },

    getUsers: async (data, user) => {
        if (!user) {
            logger.warn("Get users failed: not authenticated");
            return { error: "not auth" };
        }

        const users = await storage.getUsers();
        logger.info("Users list retrieved", { username: user, count: users.length });
        return { success: true, users };
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

        const extension = path.extname(req.file.filename).toLowerCase();
        let mimeType = 'image/jpeg';
        if (extension === '.png') mimeType = 'image/png';
        else if (extension === '.gif') mimeType = 'image/gif';
        else if (extension === '.webp') mimeType = 'image/webp';

        logger.info("Avatar uploaded successfully", { username: user, filename: req.file.filename });
        return { 
            success: true, 
            filename: req.file.filename,
            avatarUrl: `/api/user/${user}/avatar`,
            mimeType: mimeType
        };
    },

    uploadFile: async (req, user) => {
        if (!req.file) {
            logger.warn("File upload failed: no file", { username: user });
            return { error: "no file" };
        }

        const fileId = crypto.randomBytes(16).toString("hex");
        const fileInfo = {
            id: fileId,
            filename: req.file.filename,
            originalName: req.file.originalname,
            mimetype: req.file.mimetype,
            size: req.file.size,
            uploadedAt: Date.now(),
            uploadedBy: user
        };

        await storage.saveFileInfo(fileInfo);

        logger.info("File uploaded successfully", { 
            username: user, 
            fileId,
            filename: req.file.filename,
            originalName: req.file.originalname,
            size: req.file.size
        });
        
        return { 
            success: true, 
            file: {
                id: fileId,
                filename: req.file.filename,
                originalName: req.file.originalname,
                mimetype: req.file.mimetype,
                size: req.file.size,
                uploadedAt: Date.now(),
                uploadedBy: user,
                downloadUrl: `/api/download/${req.file.filename}`
            }
        };
    },

    webrtcOffer: async ({ toUser, offer, channel }, user) => {
        if (!user || !toUser || !offer) {
            logger.warn("WebRTC offer failed: missing data", { user, toUser });
            return { error: "missing offer data" };
        }

        await storage.saveWebRTCOffer(user, toUser, offer, channel);

        const offerData = JSON.stringify({
            type: "webrtc-offer",
            from: user,
            offer: offer,
            channel: channel
        });

        [...wsClients].filter(ws => ws.user === toUser && ws.readyState === 1)
            .forEach(ws => { try { ws.send(offerData); } catch {} });

        logger.info("WebRTC offer sent", { from: user, to: toUser, channel });
        return { success: true };
    },

    webrtcAnswer: async ({ toUser, answer }, user) => {
        if (!user || !toUser || !answer) {
            logger.warn("WebRTC answer failed: missing data", { user, toUser });
            return { error: "missing answer data" };
        }

        await storage.saveWebRTCAnswer(user, toUser, answer);

        const answerData = JSON.stringify({
            type: "webrtc-answer",
            from: user,
            answer: answer
        });

        [...wsClients].filter(ws => ws.user === toUser && ws.readyState === 1)
            .forEach(ws => { try { ws.send(answerData); } catch {} });

        logger.info("WebRTC answer sent", { from: user, to: toUser });
        return { success: true };
    },

    iceCandidate: async ({ toUser, candidate }, user) => {
        if (!user || !toUser || !candidate) {
            logger.warn("ICE candidate failed: missing data", { user, toUser });
            return { error: "missing candidate data" };
        }

        await storage.saveICECandidate(user, toUser, candidate);

        const candidateData = JSON.stringify({
            type: "webrtc-ice-candidate",
            from: user,
            candidate: candidate
        });

        [...wsClients].filter(ws => ws.user === toUser && ws.readyState === 1)
            .forEach(ws => { try { ws.send(candidateData); } catch {} });

        logger.info("ICE candidate sent", { from: user, to: toUser });
        return { success: true };
    },

    getWebRTCOffer: async ({ fromUser }, user) => {
        if (!user || !fromUser) {
            logger.warn("WebRTC get offer failed: missing fromUser", { user, fromUser });
            return { error: "missing fromUser" };
        }

        const offer = await storage.getWebRTCOffer(fromUser, user);
        if (offer) {
            logger.info("WebRTC offer retrieved", { from: fromUser, to: user });
            return { success: true, offer: offer.offer, channel: offer.channel };
        }
        logger.info("No WebRTC offer found", { from: fromUser, to: user });
        return { success: false };
    },

    getWebRTCAnswer: async ({ fromUser }, user) => {
        if (!user || !fromUser) {
            logger.warn("WebRTC get answer failed: missing fromUser", { user, fromUser });
            return { error: "missing fromUser" };
        }

        const answer = await storage.getWebRTCAnswer(fromUser, user);
        if (answer) {
            logger.info("WebRTC answer retrieved", { from: fromUser, to: user });
            return { success: true, answer: answer.answer };
        }
        logger.info("No WebRTC answer found", { from: fromUser, to: user });
        return { success: false };
    },

    getICECandidates: async ({ fromUser }, user) => {
        if (!user || !fromUser) {
            logger.warn("WebRTC get ICE candidates failed: missing fromUser", { user, fromUser });
            return { error: "missing fromUser" };
        }

        const candidates = await storage.getICECandidates(fromUser, user);
        logger.info("ICE candidates retrieved", { from: fromUser, to: user, count: candidates.length });
        return { success: true, candidates };
    },

    webrtcEndCall: async ({ targetUser }, user) => {
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
        
        await storage.saveVoiceMessageInfo(voiceId, user, channel, duration);
        
        logger.info("Voice message upload initiated", { user, channel, voiceId, duration });
        return { success: true, voiceId, uploadUrl: `/api/upload/voice/${voiceId}` };
    },

    getUpdates: async (data, user) => {
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
    }
};

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
            res.status(500).json({ success: false, error: "server error" });
        }
    });
};

createEndpoint('post', '/api/register', limiter(), 'register');
createEndpoint('post', '/api/login', limiter(), 'login');
createEndpoint('post', '/api/2fa/verify-login', limiter(), 'verify2FALogin');
createEndpoint('post', '/api/2fa/setup', require2FAMiddleware, 'setup2FA');
createEndpoint('post', '/api/2fa/enable', require2FAMiddleware, 'enable2FA');
createEndpoint('post', '/api/2fa/disable', require2FAMiddleware, 'disable2FA');
createEndpoint('get', '/api/2fa/status', require2FAMiddleware, 'get2FAStatus');
createEndpoint('get', '/api/updates/check', require2FAMiddleware, 'getUpdates');
createEndpoint('post', '/api/message', channelAuthMiddleware, 'sendMessage');
createEndpoint('post', '/api/message/voice-only', channelAuthMiddleware, 'sendVoiceOnly');
createEndpoint('get', '/api/messages', channelAuthMiddleware, 'getMessages', req => req.query);
createEndpoint('post', '/api/channels/create', require2FAMiddleware, 'createChannel');
createEndpoint('get', '/api/channels', require2FAMiddleware, 'getChannels');
createEndpoint('post', '/api/channels/join', require2FAMiddleware, 'joinChannel');
createEndpoint('post', '/api/channels/join-by-id', require2FAMiddleware, 'joinChannel');
createEndpoint('post', '/api/channels/leave', require2FAMiddleware, 'leaveChannel');
createEndpoint('get', '/api/channels/members', channelAuthMiddleware, 'getChannelMembers', req => req.query);
createEndpoint('post', '/api/channels/search', require2FAMiddleware, 'searchChannels');
createEndpoint('get', '/api/users', require2FAMiddleware, 'getUsers');
createEndpoint('post', '/api/webrtc/offer', require2FAMiddleware, 'webrtcOffer');
createEndpoint('post', '/api/webrtc/answer', require2FAMiddleware, 'webrtcAnswer');
createEndpoint('post', '/api/webrtc/ice-candidate', require2FAMiddleware, 'iceCandidate');
createEndpoint('get', '/api/webrtc/offer', require2FAMiddleware, 'getWebRTCOffer', req => req.query);
createEndpoint('get', '/api/webrtc/answer', require2FAMiddleware, 'getWebRTCAnswer', req => req.query);
createEndpoint('get', '/api/webrtc/ice-candidates', require2FAMiddleware, 'getICECandidates', req => req.query);
createEndpoint('post', '/api/webrtc/end-call', require2FAMiddleware, 'webrtcEndCall');
createEndpoint('post', '/api/voice/upload', require2FAMiddleware, 'uploadVoiceMessage');

app.post("/api/upload/avatar", require2FAMiddleware, avatarUpload.single("avatar"), async (req, res) => {
    try {
        const result = await actionHandlers.uploadAvatar(req, req.user);
        res.json(result);
    } catch (error) {
        logger.error("Avatar upload error", { error: error.message, user: req.user });
        res.status(500).json({ success: false, error: "upload failed" });
    }
});

app.post("/api/upload/file", require2FAMiddleware, fileUpload.single("file"), async (req, res) => {
    try {
        const result = await actionHandlers.uploadFile(req, req.user);
        res.json(result);
    } catch (error) {
        logger.error("File upload error", { error: error.message, user: req.user });
        res.status(500).json({ success: false, error: "upload failed" });
    }
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
        res.status(500).json({ success: false, error: "server error" });
    }
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
        res.status(500).json({ success: false, error: "upload failed" });
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
        const originalName = storage.getOriginalFileName(filename);
        logger.info("File download started", { filename, originalName, ip: req.ip, size: fs.statSync(filePath).size });
        
        res.setHeader('Content-Disposition', `attachment; filename="${encodeURIComponent(originalName)}"`);
        res.download(filePath, originalName, (err) => {
            if (err) {
                logger.error("File download error", { filename, error: err.message, ip: req.ip });
            } else {
                logger.info("File download completed", { filename, originalName, ip: req.ip });
            }
        });
    } else {
        logger.warn("File not found for download", { filename, ip: req.ip });
        res.status(404).json({ success: false, error: "file not found" });
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

const server = app.listen(config.server?.port || config.port, config.server?.host || "localhost", () => {
    const address = server.address();
    logger.info("Server started", { 
        host: address.address, 
        port: address.port,
        features: {
            uploads: config.features.uploads,
            voiceMessages: config.features.voiceMessages,
            webRTC: config.features.webRTC,
            twoFactor: config.features.twoFactor
        }
    });
});

server.on("upgrade", (req, socket, head) => {
    const auth = req.headers.authorization?.split(" ") || [];
    if (auth.length !== 2 || auth[0] !== "Bearer") {
        socket.destroy();
        logger.warn("WebSocket upgrade failed: no auth", { ip: req.socket.remoteAddress });
        return;
    }

    storage.validateToken(auth[1]).then(user => {
        if (!user) {
            socket.destroy();
            logger.warn("WebSocket upgrade failed: invalid token", { ip: req.socket.remoteAddress });
            return;
        }

        wss.handleUpgrade(req, socket, head, ws => {
            ws.user = user;
            wss.emit("connection", ws, req);
            logger.info("WebSocket upgraded successfully", { user, ip: req.socket.remoteAddress });
        });
    }).catch(err => {
        socket.destroy();
        logger.error("WebSocket upgrade error", { error: err.message, ip: req.socket.remoteAddress });
    });
});

const interval = setInterval(() => {
    wsClients.forEach(ws => {
        if (!ws.isAlive) {
            ws.terminate();
            logger.info("WebSocket terminated (no ping)", { user: ws.user });
            return;
        }
        ws.isAlive = false;
        ws.ping();
    });

    const now = Date.now();
    for (const [username, session] of pending2FASessions.entries()) {
        if (now - session.createdAt > 5 * 60 * 1000) {
            pending2FASessions.delete(username);
            logger.info("2FA session expired", { username });
        }
    }

    if (now % 3600000 < 30000) {
        storage.cleanupOldVoiceMessages(24 * 60 * 60)
            .then(deletedCount => {
                if (deletedCount > 0) {
                    logger.info("Cleaned up old voice message records", { deletedCount });
                }
            })
            .catch(error => {
                logger.error("Failed to cleanup voice message records", { error: error.message });
            });
    }
}, 30000);

process.on("SIGTERM", () => {
    logger.info("SIGTERM received, shutting down gracefully");
    clearInterval(interval);
    server.close(() => {
        logger.info("Server closed");
        process.exit(0);
    });
});

export default app;
