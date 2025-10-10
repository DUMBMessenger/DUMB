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

const usernameRegex = /^[a-zA-Z0-9_-]{3,20}$/;

const encryptMessage = (text, key) => {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipher('aes-256-cbc', key);
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return {
        iv: iv.toString('hex'),
        content: encrypted
    };
};

const decryptMessage = (encryptedData, key) => {
    try {
        const iv = Buffer.from(encryptedData.iv, 'hex');
        const decipher = crypto.createDecipher('aes-256-cbc', key);
        let decrypted = decipher.update(encryptedData.content, 'hex', 'utf8');
        decrypted += decipher.final('utf8');
        return decrypted;
    } catch (error) {
        throw new Error('Decryption failed');
    }
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
                logger.error("NPM API error", { error: error.message });
                resolve(null);
            });

            req.setTimeout(5000, () => {
                req.destroy();
                resolve(null);
            });

            req.end();
        });
    } catch (error) {
        logger.error("NPM update check error", { error: error.message });
        return null;
    }
};

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

const actionHandlers = {
    register: async ({ username, password }, user) => {
        if (typeof username !== "string" || typeof password !== "string") {
            logger.warn("Register failed: bad input", { username: username?.substring(0, 10) });
            return { error: "bad input" };
        }

        if (!usernameRegex.test(username.trim())) {
            logger.warn("Register failed: invalid username format", { username: username.trim() });
            return { error: "invalid username format" };
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

    updateChannel: async ({ name, newName }, user) => {
        if (!user) {
            logger.warn("Update channel failed: not authenticated");
            return { error: "not auth" };
        }

        if (!name || !newName || typeof newName !== "string" || newName.trim().length < 2) {
            logger.warn("Update channel failed: invalid parameters", { user, name, newName });
            return { error: "invalid parameters" };
        }

        const isMember = await storage.isChannelMember(name, user);
        if (!isMember) {
            logger.warn("Update channel failed: not a member", { user, name });
            return { error: "not a member" };
        }

        const updated = await storage.updateChannelName(name.trim(), newName.trim(), user);
        if (!updated) {
            logger.warn("Update channel failed: could not update", { user, name, newName });
            return { error: "update failed" };
        }

        logger.info("Channel name updated successfully", { user, oldName: name, newName });
        return { success: true, oldName: name, newName };
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
            if (message.encrypted && config.security.encryptionKey) {
                try {
                    message.text = decryptMessage(message.text, config.security.encryptionKey);
                    message.encrypted = false;
                } catch (error) {
                    logger.warn("Failed to decrypt message", { messageId: message.id, error: error.message });
                    message.text = "[encrypted message - decryption failed]";
                }
            }
            
            if (message.voice && message.voice.filename) {
                message.voice.duration = await storage.getVoiceMessageDuration(message.voice.filename) || 0;
            }
        }
        
        logger.info("Messages retrieved", { username: user, channel, count: messages.length });
        return { success: true, messages };
    },

    sendMessage: async ({ channel, text, replyTo, fileId, voiceMessage, encrypt = false }, user) => {
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

        let processedText = text ? text.trim().slice(0, config.security.maxMessageLength || 1000) : "";
        let isEncrypted = false;

        if (encrypt && config.security.encryptionKey && processedText) {
            try {
                processedText = encryptMessage(processedText, config.security.encryptionKey);
                isEncrypted = true;
            } catch (error) {
                logger.error("Message encryption failed", { user, channel, error: error.message });
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
            file: fileAttachment,
            voice: voiceAttachment,
            encrypted: isEncrypted
        };

        const saved = await storage.saveMessage(msg);
        
        if (isEncrypted && config.security.encryptionKey) {
            try {
                saved.text = decryptMessage(saved.text, config.security.encryptionKey);
                saved.encrypted = false;
            } catch (error) {
                logger.warn("Failed to decrypt saved message for broadcast", { messageId: saved.id, error: error.message });
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

        logger.info("Message sent", { username: user, channel, messageId: saved.id, hasFile: !!fileId, hasVoice: !!voiceMessage, hasText: !!text, encrypted: isEncrypted });
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
        else if (extension === '.jpg') mimeType = 'image/jpeg';

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

        const updateInfo = await checkNPMUpdates();
        
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
createEndpoint('patch', '/api/channels', require2FAMiddleware, 'updateChannel', req => ({
    name: req.query.name,
    newName: req.body.newName
}));
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
createEndpoint('post', '/api/upload/voice-message', channelAuthMiddleware, 'uploadVoiceMessage');

app.post('/api/upload/avatar', require2FAMiddleware, avatarUpload.single('avatar'), async (req, res) => {
    const startTime = Date.now();
    try {
        const result = await actionHandlers.uploadAvatar(req, req.user);
        logger.info("Avatar upload processed", {
            user: req.user,
            success: result.success,
            duration: Date.now() - startTime
        });
        res.json(result.success ? result : { success: false, ...result });
    } catch (e) {
        logger.error("Avatar upload error", {
            user: req.user,
            error: e.message,
            stack: e.stack,
            ip: req.ip
        });
        res.status(500).json({ success: false, error: "server error" });
    }
});

app.post('/api/upload/file', require2FAMiddleware, fileUpload.single('file'), async (req, res) => {
    const startTime = Date.now();
    try {
        const result = await actionHandlers.uploadFile(req, req.user);
        logger.info("File upload processed", {
            user: req.user,
            success: result.success,
            duration: Date.now() - startTime
        });
        res.json(result.success ? result : { success: false, ...result });
    } catch (e) {
        logger.error("File upload error", {
            user: req.user,
            error: e.message,
            stack: e.stack,
            ip: req.ip
        });
        res.status(500).json({ success: false, error: "server error" });
    }
});

app.post('/api/upload/voice/:voiceId', require2FAMiddleware, fileUpload.single('voice'), async (req, res) => {
    const startTime = Date.now();
    try {
        if (!req.file) {
            logger.warn("Voice upload failed: no file", { user: req.user, voiceId: req.params.voiceId });
            return res.status(400).json({ success: false, error: "no file" });
        }

        const voiceId = req.params.voiceId;
        const fileExtension = path.extname(req.file.filename);
        const newFilename = voiceId + fileExtension;

        const oldPath = path.join(config.uploads.dir, req.file.filename);
        const newPath = path.join(config.uploads.dir, newFilename);
        
        fs.renameSync(oldPath, newPath);

        await storage.updateVoiceMessageFilename(voiceId, newFilename);

        logger.info("Voice message uploaded successfully", {
            user: req.user,
            voiceId,
            filename: newFilename,
            duration: Date.now() - startTime
        });
        
        res.json({ 
            success: true, 
            voiceId: newFilename,
            message: "Voice message uploaded successfully" 
        });
    } catch (e) {
        logger.error("Voice upload error", {
            user: req.user,
            voiceId: req.params.voiceId,
            error: e.message,
            stack: e.stack,
            ip: req.ip
        });
        res.status(500).json({ success: false, error: "server error" });
    }
});

app.get('/api/user/:username/avatar', async (req, res) => {
    try {
        const avatar = await storage.getUserAvatar(req.params.username);
        if (!avatar) {
            return res.status(404).json({ error: "avatar not found" });
        }

        const avatarPath = path.join(config.uploads.dir, avatar);
        if (!fs.existsSync(avatarPath)) {
            return res.status(404).json({ error: "avatar file not found" });
        }

        const extension = path.extname(avatar).toLowerCase();
        let mimeType = 'image/jpeg';
        if (extension === '.png') mimeType = 'image/png';
        else if (extension === '.gif') mimeType = 'image/gif';
        else if (extension === '.webp') mimeType = 'image/webp';
        else if (extension === '.jpg') mimeType = 'image/jpeg';

        res.setHeader('Content-Type', mimeType);
        res.setHeader('Cache-Control', 'public, max-age=86400');
        res.sendFile(avatarPath);
    } catch (e) {
        logger.error("Avatar serve error", { username: req.params.username, error: e.message });
        res.status(500).json({ error: "server error" });
    }
});

app.get('/api/download/:filename', async (req, res) => {
    try {
        const filePath = path.join(config.uploads.dir, req.params.filename);
        if (!fs.existsSync(filePath)) {
            return res.status(404).json({ error: "file not found" });
        }

        const fileInfo = await storage.getFileInfoByFilename(req.params.filename);
        if (fileInfo) {
            res.setHeader('Content-Disposition', `attachment; filename="${encodeURIComponent(fileInfo.originalName)}"`);
            res.setHeader('Content-Type', fileInfo.mimetype);
        } else {
            res.setHeader('Content-Disposition', 'attachment');
            res.setHeader('Content-Type', 'application/octet-stream');
        }

        res.sendFile(filePath);
    } catch (e) {
        logger.error("File download error", { filename: req.params.filename, error: e.message });
        res.status(500).json({ error: "server error" });
    }
});

app.get('/api/events', authMiddleware, (req, res) => {
    res.writeHead(200, {
        'Content-Type': 'text/event-stream',
        'Cache-Control': 'no-cache',
        'Connection': 'keep-alive'
    });

    const client = { id: Date.now(), res, user: req.user };
    sseClients.add(client);

    req.on('close', () => {
        sseClients.delete(client);
        logger.info("SSE client disconnected", { username: req.user });
    });

    logger.info("SSE client connected", { username: req.user });
});

const wss = new WebSocketServer({ port: config.ws.port });
wss.on('connection', async (ws, req) => {
    const url = new URL(req.url || "", `http://${req.headers.host}`);
    const token = url.searchParams.get("token");

    if (!token) {
        ws.close(1008, "no token");
        return;
    }

    const user = await storage.validateToken(token);
    if (!user) {
        ws.close(1008, "invalid token");
        return;
    }

    ws.user = user;
    wsClients.add(ws);
    logger.info("WebSocket client connected", { username: user });

    ws.on('message', async (data) => {
        try {
            const msg = JSON.parse(data);
            if (msg.type === "ping") {
                ws.send(JSON.stringify({ type: "pong" }));
                return;
            }
        } catch (e) {
            logger.warn("WebSocket message parse error", { username: user, error: e.message });
        }
    });

    ws.on('close', () => {
        wsClients.delete(ws);
        logger.info("WebSocket client disconnected", { username: user });
    });

    ws.on('error', (error) => {
        logger.error("WebSocket error", { username: user, error: error.message });
    });
});

setInterval(() => {
    const now = Date.now();
    wsClients.forEach(ws => {
        if (ws.readyState === 1) {
            try {
                ws.ping();
            } catch (e) {
                logger.warn("WebSocket ping failed", { username: ws.user, error: e.message });
            }
        }
    });

    for (let [username, session] of pending2FASessions) {
        if (now - session.createdAt > 5 * 60 * 1000) {
            pending2FASessions.delete(username);
            logger.info("Expired 2FA session cleaned up", { username });
        }
    }
}, 30000);

app.listen(config.port, () => {
    logger.info("Server started", { port: config.port });
});
