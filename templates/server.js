// hook (insert evil emoji)
import { loadPlugins, applyPlugins } from "./dumix.js";
await loadPlugins("./plugins");
await applyPlugins();

// imports
import express from "express";
import cors from "cors";
import multer from "multer";
import { WebSocketServer } from "./modules/websocket.js";
import { Crypto as crypto } from "./modules/crypto.js";
import fs from "fs";
import path from "path";
import config from "./config.js";
const emailService = new EmailService(config.email);
import * as storage from "./storage/storage.js";
import { TOTP as speakeasy } from "./modules/speakeasy.js";
import { QRCode } from "./modules/qrcode.js";
import { SSEServer } from "./modules/sse.js";
import { EmailService } from './modules/email.js';
import { anse2_encrypt_wasm, anse2_decrypt_wasm, anse2_init_wasm } from "@akaruineko1/anse2";
import { RedisService } from "./modules/redis.js";
import { Logger } from './modules/logger.js';
import https from "https";

anse2_init_wasm();

const app = express();
app.use(cors({ origin: config.cors.origin }));
app.use(express.json({ limit: "1mb" }));

const redisService = new RedisService(config.redis || { enabled: false });
await redisService.connect();

if (config.features.uploads && !fs.existsSync(config.uploads.dir)) {
    fs.mkdirSync(config.uploads.dir, { recursive: true });
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
        return res.status(401).json({ error: "no auth" });
    }

    const user = await storage.validateToken(auth[1]);
    if (!user) {
        return res.status(401).json({ error: "invalid token" });
    }

    req.user = user;
    next();
};

const require2FAMiddleware = async (req, res, next) => {
    await authMiddleware(req, res, async () => {
        const twoFactorEnabled = await storage.isTwoFactorEnabled(req.user);
        if (twoFactorEnabled) {
            const session = pending2FASessions.get(req.user);
            if (!session || !session.twoFactorVerified) {
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
            return res.status(429).json({ error: "rate limit" });
        }
        next();
    };
};

const cacheMiddleware = (ttlSeconds = 300) => {
    return async (req, res, next) => {
        if (!config.redis?.enabled) {
            return next();
        }

        const cacheKey = `route:${req.method}:${req.originalUrl}:${req.user || 'anon'}`;
        
        try {
            const cached = await redisService.get(cacheKey);
            if (cached) {
                return res.json(cached);
            }
        } catch (error) {}

        const originalJson = res.json;
        res.json = function(data) {
            if (data.success && !data.error) {
                redisService.set(cacheKey, data, ttlSeconds).catch(err => {});
            }
            originalJson.call(this, data);
        };

        next();
    };
};

const checkNPMUpdates = async () => {
    if (!config.npm?.packageName) {
        return null;
    }

    try {
        const options = {
            hostname: 'registry.npmjs.org',
            path: `/${config.npm.packageName}/latest`,
            method: 'GET',
            headers: {
                'User-Agent': 'ChatApp-Server'
            }
        };

        return new Promise((resolve, reject) => {
            const req = https.request(options, (res) => {
                let data = '';
                res.on('data', chunk => data += chunk);
                res.on('end', () => {
                    if (res.statusCode === 200) {
                        const pkgInfo = JSON.parse(data);
                        resolve({
                            version: pkgInfo.version,
                            description: pkgInfo.description,
                            lastModified: pkgInfo.time?.modified
                        });
                    } else {
                        resolve(null);
                    }
                });
            });

            req.on('error', (error) => {
                resolve(null);
            });

            req.setTimeout(5000, () => {
                req.destroy();
                resolve(null);
            });

            req.end();
        });
    } catch (error) {
        return null;
    }
};

const actionHandlers = {
    register: async ({ username, password }, user) => {
        if (typeof username !== "string" || typeof password !== "string") {
            return { error: "bad input" };
        }

        if (!storage.validateUsername(username.trim())) {
            return { error: "invalid username format" };
        }

        try {
            const result = await storage.registerUser(username.trim(), password.trim());
            if (result) {
                return { success: true };
            } else {
                return { error: "user exists" };
            }
        } catch (error) {
            return { error: error.message };
        }
    },

    login: async ({ username, password, twoFactorToken }, user) => {
        const u = await storage.authenticate(username, password);
        if (!u) {
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
                
                return { 
                    success: false, 
                    requires2FA: true,
                    sessionId,
                    message: "Two-factor authentication required" 
                };
            }

            const secret = await storage.getTwoFactorSecret(username);
            const verified = speakeasy.verify({
                secret: secret,
                encoding: 'base32',
                token: twoFactorToken,
                window: 1
            });

            if (!verified) {
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
        
        return { success: true, token, twoFactorEnabled };
    },

    verify2FALogin: async ({ username, sessionId, twoFactorToken }, user) => {
        if (!username || !sessionId || !twoFactorToken) {
            return { error: "missing parameters" };
        }

        const session = pending2FASessions.get(username);
        if (!session || session.sessionId !== sessionId) {
            return { error: "invalid session" };
        }

        if (Date.now() - session.createdAt > 5 * 60 * 1000) {
            pending2FASessions.delete(username);
            return { error: "session expired" };
        }

        const secret = await storage.getTwoFactorSecret(username);
        const verified = speakeasy.verify({
            secret: secret,
            encoding: 'base32',
            token: twoFactorToken,
            window: 1
        });

        if (!verified) {
            return { error: "invalid 2fa token" };
        }

        session.twoFactorVerified = true;
        pending2FASessions.set(username, session);

        const token = genToken();
        await storage.saveToken(username, token, Date.now() + config.security.tokenTTL);
        
        return { 
            success: true, 
            token, 
            twoFactorEnabled: true,
            message: "Two-factor authentication successful" 
        };
    },

    setup2FA: async (data, user) => {
        if (!user) {
            return { error: "not auth" };
        }

        const secret = speakeasy.generateSecret({
            name: `ChatApp:${user}`,
            issuer: "ChatApp"
        });

        await storage.setTwoFactorSecret(user, secret.base32);
        
        const qrCodeUrl = await QRCode.toDataURL(secret.otpauth_url);
        
        return { success: true, secret: secret.base32, qrCodeUrl };
    },

    enable2FA: async ({ token }, user) => {
        if (!user) {
            return { error: "not auth" };
        }

        const secret = await storage.getTwoFactorSecret(user);
        if (!secret) {
            return { error: "setup required" };
        }

        const verified = speakeasy.verify({
            secret: secret,
            encoding: 'base32',
            token: token,
            window: 1
        });

        if (!verified) {
            return { error: "invalid token" };
        }

        await storage.enableTwoFactor(user, true);
        return { success: true };
    },

    disable2FA: async ({ password }, user) => {
        if (!user) {
            return { error: "not auth" };
        }

        const authenticated = await storage.authenticate(user, password);
        if (!authenticated) {
            return { error: "invalid password" };
        }

        await storage.enableTwoFactor(user, false);
        await storage.setTwoFactorSecret(user, null);
        
        return { success: true };
    },

    get2FAStatus: async (data, user) => {
        if (!user) {
            return { error: "not auth" };
        }

        const enabled = await storage.isTwoFactorEnabled(user);
        return { success: true, enabled };
    },

    createChannel: async ({ name, customId }, user) => {
        if (!user || !name || typeof name !== "string" || name.trim().length < 2) {
            return { error: "invalid channel name" };
        }

        const channelId = await storage.createChannel(name.trim(), user, customId);
        if (!channelId) {
            return { error: "channel exists" };
        }

        if (config.redis?.enabled) {
            redisService.invalidateUserChannels(user).catch(err => {});
        }

        return { success: true, channelId, channel: name.trim() };
    },

    getChannels: async (data, user) => {
        if (!user) {
            return { error: "not auth" };
        }

        if (config.redis?.enabled) {
            try {
                const cached = await redisService.getCachedUserChannels(user);
                if (cached) {
                    return { success: true, channels: cached };
                }
            } catch (error) {}
        }

        const channels = await storage.getChannels(user);
        
        if (config.redis?.enabled) {
            redisService.cacheUserChannels(user, channels, 600).catch(err => {});
        }

        return { success: true, channels };
    },

    searchChannels: async ({ query }, user) => {
        if (!user) {
            return { error: "not auth" };
        }

        if (query === undefined || query === null) {
            return { error: "invalid query" };
        }

        const channels = await storage.searchChannels(query);
        return { success: true, channels };
    },

    joinChannel: async ({ channel }, user) => {
        if (!user || !channel || typeof channel !== "string") {
            return { error: "invalid channel" };
        }

        const result = await storage.joinChannel(channel, user);
        if (!result) {
            return { error: "invalid channel" };
        }

        if (config.redis?.enabled) {
            redisService.invalidateUserChannels(user).catch(err => {});
        }

        return { success: true };
    },

    leaveChannel: async ({ channel }, user) => {
        if (!user || !channel || typeof channel !== "string") {
            return { error: "invalid channel" };
        }

        const result = await storage.leaveChannel(channel, user);
        if (!result) {
            return { error: "not a member" };
        }

        if (config.redis?.enabled) {
            redisService.invalidateUserChannels(user).catch(err => {});
        }

        return { success: true };
    },

    getChannelMembers: async ({ channel }, user) => {
        if (!user || !channel || typeof channel !== "string") {
            return { error: "invalid channel" };
        }

        if (!await storage.isChannelMember(channel, user)) {
            return { error: "not a channel member" };
        }

        const members = await storage.getChannelMembers(channel);
        return { success: true, members };
    },

    updateChannel: async ({ name, newName }, user) => {
        if (!user) {
            return { error: "not auth" };
        }

        if (!name || !newName || typeof newName !== "string" || newName.trim().length < 2) {
            return { error: "invalid parameters" };
        }

        const isMember = await storage.isChannelMember(name, user);
        if (!isMember) {
            return { error: "not a member" };
        }

        const updated = await storage.updateChannelName(name.trim(), newName.trim(), user);
        if (!updated) {
            return { error: "update failed" };
        }

        if (config.redis?.enabled) {
            redisService.invalidateChannel(name).catch(err => {});
            redisService.invalidateChannel(newName).catch(err => {});
        }

        return { success: true, oldName: name, newName };
    },

    getMessages: async ({ channel, limit = 50, before }, user) => {
        if (!user || !channel || typeof channel !== "string") {
            return { error: "invalid parameters" };
        }

        if (!await storage.isChannelMember(channel, user)) {
            return { error: "not a channel member" };
        }

        if (config.redis?.enabled) {
            try {
                const cached = await redisService.getCachedMessages(channel);
                if (cached) {
                    return { success: true, messages: cached };
                }
            } catch (error) {}
        }

        const messages = await storage.getMessages(channel, Math.min(limit, 100), before);
        
        for (let message of messages) {
            if (message.voice && message.voice.filename) {
                message.voice.duration = await storage.getVoiceMessageDuration(message.voice.filename) || 0;
            }
            
            if (message.replyTo && !message.replyToMessage) {
                const parentMessage = await storage.getMessageById(message.replyTo);
                if (parentMessage) {
                    message.replyToMessage = {
                        id: parentMessage.id,
                        from: parentMessage.from,
                        text: parentMessage.text?.substring(0, 100) + (parentMessage.text?.length > 100 ? '...' : ''),
                        ts: parentMessage.ts,
                        hasFile: !!parentMessage.file,
                        hasVoice: !!parentMessage.voice
                    };
                }
            }
        }
        
        if (config.redis?.enabled) {
            redisService.cacheMessages(channel, messages, 60).catch(err => {});
        }

        return { success: true, messages };
    },

    getMessage: async ({ messageId }, user) => {
        if (!user || !messageId) {
            return { error: "invalid parameters" };
        }

        const message = await storage.getMessageById(messageId);
        if (!message) {
            return { error: "message not found" };
        }

        if (!await storage.isChannelMember(message.channel, user)) {
            return { error: "not a channel member" };
        }

        return { success: true, message };
    },

    sendMessage: async ({ channel, text, replyTo, fileId, voiceMessage, encrypt = false }, user) => {
        if (!user || !channel) {
            return { error: "bad input" };
        }

        if (!text && !fileId && !voiceMessage) {
            return { error: "no content" };
        }

        if (!await storage.isChannelMember(channel, user)) {
            return { error: "not a channel member" };
        }

        let replyToMessage = null;
        if (replyTo) {
            replyToMessage = await storage.getMessageById(replyTo);
            if (!replyToMessage) {
                return { error: "reply message not found" };
            }
            if (replyToMessage.channel !== channel) {
                return { error: "reply message from different channel" };
            }
        }

        let processedText = text ? text.trim().slice(0, config.security.maxMessageLength || 1000) : "";
        let isEncrypted = false;

        if (encrypt && config.security.encryptionKey && processedText) {
            try {
                const encoder = new TextEncoder();
                const inputBytes = encoder.encode(processedText);
                const encryptedBytes = anse2_encrypt_wasm(inputBytes, config.security.encryptionKey);
                processedText = Buffer.from(encryptedBytes).toString('base64');
                isEncrypted = true;
            } catch (error) {
                return { error: "encryption failed" };
            }
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
            text: processedText,
            ts: Date.now(),
            replyTo: replyTo || null,
            replyToMessage: replyToMessage ? {
                id: replyToMessage.id,
                from: replyToMessage.from,
                text: replyToMessage.text,
                ts: replyToMessage.ts,
                hasFile: !!replyToMessage.file,
                hasVoice: !!replyToMessage.voice
            } : null,
            file: fileAttachment,
            voice: voiceAttachment,
            encrypted: isEncrypted
        };

        const saved = await storage.saveMessage(msg);
        
        if (isEncrypted && config.security.encryptionKey) {
            try {
                const encryptedBytes = Buffer.from(saved.text, 'base64');
                const decryptedBytes = anse2_decrypt_wasm(encryptedBytes, config.security.encryptionKey);
                const decoder = new TextDecoder();
                saved.text = decoder.decode(decryptedBytes);
                saved.encrypted = false;
            } catch (error) {
                saved.text = "[encrypted message]";
            }
        }
        
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

        if (config.redis?.enabled) {
            redisService.invalidateChannel(channel).catch(err => {});
        }

        return { success: true, message: saved };
    },

    sendVoiceOnly: async ({ channel, voiceMessage }, user) => {
        if (!user || !channel || !voiceMessage) {
            return { error: "bad input" };
        }

        if (!await storage.isChannelMember(channel, user)) {
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
            voice: voiceAttachment,
            encrypted: false
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

        if (config.redis?.enabled) {
            redisService.invalidateChannel(channel).catch(err => {});
        }

        return { success: true, message: saved };
    },

    getUsers: async (data, user) => {
        if (!user) {
            return { error: "not auth" };
        }

        const users = await storage.getUsers();
        return { success: true, users };
    },

    uploadAvatar: async (req, user) => {
        if (!req.file) {
            return { error: "no file" };
        }

        const result = await storage.updateUserAvatar(user, req.file.filename);
        if (!result) {
            return { error: "user not found" };
        }

        const extension = path.extname(req.file.filename).toLowerCase();
        let mimeType = 'image/jpeg';
        if (extension === '.png') mimeType = 'image/png';
        else if (extension === '.gif') mimeType = 'image/gif';
        else if (extension === '.webp') mimeType = 'image/webp';
        else if (extension === '.jpg') mimeType = 'image/jpeg';

        return { 
            success: true, 
            filename: req.file.filename,
            avatarUrl: `/api/user/${user}/avatar`,
            mimeType: mimeType
        };
    },

    uploadFile: async (req, user) => {
        if (!req.file) {
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

        return { success: true };
    },

    webrtcAnswer: async ({ toUser, answer }, user) => {
        if (!user || !toUser || !answer) {
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

        return { success: true };
    },

    iceCandidate: async ({ toUser, candidate }, user) => {
        if (!user || !toUser || !candidate) {
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

        return { success: true };
    },

    getWebRTCOffer: async ({ fromUser }, user) => {
        if (!user || !fromUser) {
            return { error: "missing fromUser" };
        }

        const offer = await storage.getWebRTCOffer(fromUser, user);
        if (offer) {
            return { success: true, offer: offer.offer, channel: offer.channel };
        }
        return { success: false };
    },

    getWebRTCAnswer: async ({ fromUser }, user) => {
        if (!user || !fromUser) {
            return { error: "missing fromUser" };
        }

        const answer = await storage.getWebRTCAnswer(fromUser, user);
        if (answer) {
            return { success: true, answer: answer.answer };
        }
        return { success: false };
    },

    getICECandidates: async ({ fromUser }, user) => {
        if (!user || !fromUser) {
            return { error: "missing fromUser" };
        }

        const candidates = await storage.getICECandidates(fromUser, user);
        return { success: true, candidates };
    },

    webrtcEndCall: async ({ targetUser }, user) => {
        if (!user || !targetUser) {
            return { error: "missing targetUser" };
        }

        const endCallData = JSON.stringify({ type: "webrtc-end-call", from: user });

        [...wsClients].filter(ws => ws.user === targetUser && ws.readyState === 1)
            .forEach(ws => { try { ws.send(endCallData); } catch {} });

        return { success: true };
    },

    uploadVoiceMessage: async ({ channel, duration }, user) => {
        if (!user || !channel) {
            return { error: "missing parameters" };
        }

        const voiceId = crypto.randomBytes(16).toString("hex") + ".ogg";
        
        await storage.saveVoiceMessageInfo(voiceId, user, channel, duration);
        
        return { success: true, voiceId, uploadUrl: `/api/upload/voice/${voiceId}` };
    },

    verifyEmail: async ({ email, code }, user) => {
        if (!user || !email || !code) {
            return { error: "missing parameters" };
        }

        const verified = await storage.verifyEmailCode(user, email, code);
        if (!verified) {
            return { error: "invalid code or email" };
        }

        await storage.setUserEmail(user, email);
        return { success: true };
    },

    requestPasswordReset: async ({ email }) => {
        if (!email) {
            return { error: "email required" };
        }

        const user = await storage.getUserByEmail(email);
        if (!user) {
            return { success: true, message: "If email exists, reset instructions sent" };
        }

        const resetToken = crypto.randomBytes(32).toString('hex');
        await storage.createPasswordReset(user, resetToken);

        await emailService.sendPasswordResetEmail(email, resetToken);

        return { success: true, message: "If email exists, reset instructions sent" };
    },

    resetPassword: async ({ token, newPassword }) => {
        if (!token || !newPassword) {
            return { error: "missing parameters" };
        }

        const result = await storage.usePasswordReset(token, newPassword);
        if (!result) {
            return { error: "invalid or expired token" };
        }

        return { success: true };
    },

    sendVerificationEmail: async ({ email }, user) => {
        if (!user || !email) {
            return { error: "missing parameters" };
        }

        const existingUser = await storage.getUserByEmail(email);
        if (existingUser && existingUser !== user) {
            return { error: "email already in use" };
        }

        const verificationCode = Math.random().toString().substring(2, 8);
        await storage.createEmailVerification(user, email, verificationCode);

        const sent = await emailService.sendVerificationEmail(email, verificationCode);
        
        if (!sent) {
            return { error: "failed to send email" };
        }

        return { success: true };
    },

    getUpdates: async (data, user) => {
        if (!user) {
            return { error: "not auth" };
        }

        const updateInfo = await checkNPMUpdates();
        
        if (updateInfo) {
            return { 
                success: true, 
                hasUpdates: true, 
                updateInfo 
            };
        } else {
            return { 
                success: true, 
                hasUpdates: false 
            };
        }
    }
};

const createEndpoint = (method, path, middleware, action, paramMap = null) => {
    app[method](path, middleware, async (req, res) => {
        try {
            const params = paramMap ? paramMap(req) : req.method === 'GET' ? req.query : req.body;
            const result = await actionHandlers[action](params, req.user);
            res.json(result.success ? result : { success: false, ...result });
        } catch (e) {
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
createEndpoint('get', '/api/messages', [channelAuthMiddleware, cacheMiddleware(60)], 'getMessages', req => req.query);
createEndpoint('get', '/api/message/:messageId', channelAuthMiddleware, 'getMessage');
createEndpoint('post', '/api/channels/create', require2FAMiddleware, 'createChannel');
createEndpoint('get', '/api/channels', [require2FAMiddleware, cacheMiddleware(600)], 'getChannels');
createEndpoint('patch', '/api/channels', require2FAMiddleware, 'updateChannel', req => ({
    name: req.query.name,
    newName: req.body.newName
}));
createEndpoint('post', '/api/channels/join', require2FAMiddleware, 'joinChannel');
createEndpoint('post', '/api/channels/join-by-id', require2FAMiddleware, 'joinChannel');
createEndpoint('post', '/api/channels/leave', require2FAMiddleware, 'leaveChannel');
createEndpoint('get', '/api/channels/members', channelAuthMiddleware, 'getChannelMembers', req => req.query);
createEndpoint('post', '/api/channels/search', require2FAMiddleware, 'searchChannels');
createEndpoint('get', '/api/users', [require2FAMiddleware, cacheMiddleware(300)], 'getUsers');
createEndpoint('post', '/api/webrtc/offer', require2FAMiddleware, 'webrtcOffer');
createEndpoint('post', '/api/webrtc/answer', require2FAMiddleware, 'webrtcAnswer');
createEndpoint('post', '/api/webrtc/ice-candidate', require2FAMiddleware, 'iceCandidate');
createEndpoint('get', '/api/webrtc/offer', require2FAMiddleware, 'getWebRTCOffer', req => req.query);
createEndpoint('get', '/api/webrtc/answer', require2FAMiddleware, 'getWebRTCAnswer', req => req.query);
createEndpoint('get', '/api/webrtc/ice-candidates', require2FAMiddleware, 'getICECandidates', req => req.query);
createEndpoint('post', '/api/webrtc/end-call', require2FAMiddleware, 'webrtcEndCall');
createEndpoint('post', '/api/voice/upload', require2FAMiddleware, 'uploadVoiceMessage');
createEndpoint('post', '/api/email/verify', require2FAMiddleware, 'verifyEmail');
createEndpoint('post', '/api/email/send-verification', require2FAMiddleware, 'sendVerificationEmail');
createEndpoint('post', '/api/auth/reset-password', limiter(), 'requestPasswordReset');
createEndpoint('post', '/api/auth/reset-password/confirm', limiter(), 'resetPassword');

app.get("/api/ping", (req, res) => {
    res.json({ success: true, message: "pong" });
});

app.get("/api/admin/redis-stats", require2FAMiddleware, async (req, res) => {
    try {
        const stats = await redisService.getStats();
        res.json({ success: true, stats });
    } catch (error) {
        res.status(500).json({ success: false, error: "Failed to get Redis stats" });
    }
});

app.post("/api/upload/avatar", require2FAMiddleware, avatarUpload.single("avatar"), async (req, res) => {
    try {
        const result = await actionHandlers.uploadAvatar(req, req.user);
        res.json(result);
    } catch (error) {
        res.status(500).json({ success: false, error: "upload failed" });
    }
});

app.post("/api/upload/file", require2FAMiddleware, fileUpload.single("file"), async (req, res) => {
    try {
        const result = await actionHandlers.uploadFile(req, req.user);
        res.json(result);
    } catch (error) {
        res.status(500).json({ success: false, error: "upload failed" });
    }
});

app.get("/api/user/:username/avatar", async (req, res) => {
    try {
        const users = await storage.getUsers();
        const user = users.find(u => u.username === req.params.username);

        if (!user?.avatar) {
            return res.status(404).json({ error: "avatar not found" });
        }

        if (!fs.existsSync(path.join(config.uploads.dir, user.avatar))) {
            return res.status(404).json({ error: "avatar file not found" });
        }

        res.sendFile(user.avatar, { root: config.uploads.dir });
    } catch (error) {
        res.status(500).json({ success: false, error: "server error" });
    }
});

app.post("/api/upload/voice/:voiceId", require2FAMiddleware, multer().single('voice'), async (req, res) => {
    try {
        const voiceId = req.params.voiceId;
        
        if (!req.file) {
            return res.status(400).json({ success: false, error: "No file uploaded" });
        }

        const filePath = path.join(config.uploads.dir, voiceId);
        await fs.promises.writeFile(filePath, req.file.buffer);
        
        res.json({ success: true, voiceId });
    } catch (error) {
        res.status(500).json({ success: false, error: "upload failed" });
    }
});

app.get("/api/download/:filename", (req, res) => {
    const filename = req.params.filename;
    const filePath = path.join(config.uploads.dir, filename);

    if (filename.includes('..') || filename.includes('/') || filename.includes('\\')) {
        return res.status(400).json({ error: "invalid filename" });
    }

    if (fs.existsSync(filePath)) {
        const originalName = storage.getOriginalFileName(filename);
        
        res.setHeader('Content-Disposition', `attachment; filename="${encodeURIComponent(originalName)}"`);
        res.download(filePath, originalName);
    } else {
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

    req.on("close", () => {
        sseClients.delete(client);
    });

    res.write(`data: ${JSON.stringify({ type: "connected", clientId: client.id })}\n\n`);
});

const wss = new WebSocketServer({ noServer: true });

wss.on("connection", (ws, req) => {
    wsClients.add(ws);
    ws.isAlive = true;

    ws.on("pong", () => { ws.isAlive = true; });
    ws.on("close", () => {
        wsClients.delete(ws);
    });

    ws.on("message", async data => {
        try {
            const payload = JSON.parse(data.toString());
            const result = await actionHandlers[payload.action]?.(payload, ws.user);
            if (result) ws.send(JSON.stringify(result));
        } catch (e) {}
    });
});

const server = app.listen(config.server.port, config.server.host, () => {
    const address = server.address();
    console.log(`Server started on ${address.address}:${address.port}`);
});

server.on("upgrade", (req, socket, head) => {
    let token;
    const auth = req.headers.authorization?.split(" ") || [];
    if (auth.length === 2 && auth[0] === "Bearer") {
        token = auth[1];
    } else {
        const url = new URL(req.url, `http://${req.headers.host}`);
        token = url.searchParams.get('token');
    }

    if (!token) {
        socket.destroy();
        return;
    }

    storage.validateToken(token).then(user => {
        if (!user) {
            socket.destroy();
            return;
        }

        wss.handleUpgrade(req, socket, head, ws => {
            ws.user = user;
            wss.emit("connection", ws, req);
        });
    }).catch(err => {
        socket.destroy();
    });
});

const interval = setInterval(() => {
    wsClients.forEach(ws => {
        if (!ws.isAlive) {
            ws.terminate();
            return;
        }
        ws.isAlive = false;
        ws.ping();
    });

    const now = Date.now();
    for (const [username, session] of pending2FASessions.entries()) {
        if (now - session.createdAt > 5 * 60 * 1000) {
            pending2FASessions.delete(username);
        }
    }

    if (now % 3600000 < 30000) {
        storage.cleanupOldVoiceMessages(24 * 60 * 60).catch(error => {});
    }
}, 30000);

process.on("SIGTERM", () => {
    clearInterval(interval);
    server.close(() => {
        process.exit(0);
    });
});

export default app;
