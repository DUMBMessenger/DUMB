import express from "express";
import cors from "cors";
import multer from "multer";
import fs from "fs";
import path from "path";
import config from "./config.js";
import https from "https";
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import { createModuleLoader } from "./modules/loader.js";

const __filename = fileURLToPath((typeof document === "undefined") ? import.meta.url : "file://" + process.argv[1]);
const __dirname = dirname(__filename);

const moduleLoader = createModuleLoader(config);

try {
    await moduleLoader.init();
} catch (error) {
    console.error('Failed to initialize modules:', error);
    process.exit(1);
}

const storage = moduleLoader.get('storage');
if (!storage) {
    console.error('Critical: Storage module not found!');
    process.exit(1);
}

const crypto = moduleLoader.get('crypto');
const speakeasy = moduleLoader.get('speakeasy');
const QRCode = moduleLoader.get('QRCode');
const WebSocketServer = moduleLoader.get('WebSocketServer');
const DCPProtocol = moduleLoader.get('DCPProtocol');
const EmailService = moduleLoader.get('email');
const redisService = moduleLoader.get('redis'); // Исправлено: redisService вместо RedisService
const logger = moduleLoader.get('logger') || console;

// Получаем уже созданные экземпляры из ModuleLoader
const botSystem = moduleLoader.get('bots');
const moderationSystem = moduleLoader.get('moderation');
const FirewallClass = moduleLoader.get('firewall');
const RateLimiterClass = moduleLoader.get('rateLimiter');
const ProxyManagerClass = moduleLoader.get('proxy');
const NotificationManagerClass = moduleLoader.get('NotificationManager');

// Отладочная информация
console.log('\n=== MODULE LOADER DEBUG ===');
console.log('Available modules:', Array.from(moduleLoader.modules.keys()));
console.log('botSystem type:', typeof botSystem);
console.log('moderationSystem type:', typeof moderationSystem);
console.log('FirewallClass type:', typeof FirewallClass);
console.log('RateLimiterClass type:', typeof RateLimiterClass);
console.log('===========================\n');

// Проверяем и инициализируем системы
if (!botSystem) {
    logger.warn('Server', 'Bot system not available');
    botSystem = getFallbackBotSystem();
} else {
    logger.info('Server', 'Bot system loaded from ModuleLoader');
}

if (!moderationSystem) {
    logger.warn('Server', 'Moderation system not available');
    moderationSystem = getFallbackModerationSystem();
} else {
    logger.info('Server', 'Moderation system loaded from ModuleLoader');
}

let firewall = null;
if (FirewallClass && typeof FirewallClass === 'function') {
    try {
        firewall = new FirewallClass(config.firewall || {});
        logger.info('Server', 'Firewall initialized');
    } catch (error) {
        logger.error('Server', `Failed to initialize firewall: ${error.message}`);
        firewall = getFallbackFirewall();
    }
} else {
    logger.warn('Server', 'Firewall not available');
    firewall = getFallbackFirewall();
}

let globalRateLimiter = null;
if (RateLimiterClass && typeof RateLimiterClass === 'function') {
    try {
        globalRateLimiter = new RateLimiterClass(
            config.rateLimit?.windowMs || 60000,
            config.rateLimit?.max || 100
        );
        logger.info('Server', 'Rate limiter initialized');
    } catch (error) {
        logger.error('Server', `Failed to initialize rate limiter: ${error.message}`);
        globalRateLimiter = getFallbackRateLimiter();
    }
} else {
    logger.warn('Server', 'Rate limiter not available');
    globalRateLimiter = getFallbackRateLimiter();
}

// Вспомогательные функции для fallback-объектов
function getFallbackBotSystem() {
    return { 
        processMessageForBots: async () => {},
        getUserBots: () => [],
        registerBot: async () => { throw new Error('Bot system not available'); },
        deleteBot: async () => { throw new Error('Bot system not available'); },
        wss: null
    };
}

function getFallbackModerationSystem() {
    return {
        checkBan: async () => ({ banned: false, reason: null }),
        banUser: async () => ({ success: false }),
        unbanUser: async () => ({ success: false }),
        warnUser: async () => ({ success: false })
    };
}

function getFallbackFirewall() {
    return {
        middleware: () => (req, res, next) => next()
    };
}

function getFallbackRateLimiter() {
    return {
        middleware: () => (req, res, next) => next()
    };
}

let notificationManager = null;
let notificationService = null;
if (NotificationManagerClass) {
    notificationManager = new NotificationManagerClass(storage, null, null);
    notificationService = notificationManager.getService();
} else {
    logger.warn('Server', 'Notifications not available');
    notificationService = {
        sendWelcomeNotification: async () => {},
        onNewMessage: async () => {},
        wss: null,
        sse: null
    };
    notificationManager = {
        middleware: () => (req, res, next) => next(),
        setupRoutes: () => {},
        getService: () => notificationService
    };
}

let proxyManager = null;
if (config.proxy?.enabled && ProxyManagerClass) {
    try {
        proxyManager = new ProxyManagerClass(config.proxy);
        logger.info('Server', 'Proxy manager initialized');
    } catch (error) {
        logger.error('Server', `Failed to initialize proxy manager: ${error.message}`);
        proxyManager = null;
    }
} else if (config.proxy?.enabled && !ProxyManagerClass) {
    logger.warn('Server', 'Proxy enabled in config but proxy module not available');
}

if (config.security?.encryptionKey) {
    try {
        const { anse2_init_wasm, anse2_encrypt_wasm, anse2_decrypt_wasm } = await import("@akaruineko1/anse2");
        anse2_init_wasm();
        moduleLoader.modules.set('anse2', { anse2_encrypt_wasm, anse2_decrypt_wasm });
    } catch (error) {
        logger.error('Server', `WASM encryption not available: ${error.message}`);
    }
}

const app = express();
app.use(cors({ origin: config.cors.origin }));
app.use(express.json({ limit: "1mb" }));

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
        const allowedTypes = isAvatar 
            ? config.uploads.allowedAvatarMime || config.uploads.allowedMime
            : config.uploads.allowedMime;
        
        if (!allowedTypes.includes(file.mimetype)) {
            cb(new Error(`File type not allowed. Allowed types: ${allowedTypes.join(', ')}`), false);
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

        let request;
        if (proxyManager && proxyManager.getProxyAgent) {
            const agent = proxyManager.getProxyAgent();
            if (agent) {
                options.agent = agent;
            }
        }

        return new Promise((resolve, reject) => {
            request = https.request(options, (res) => {
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

            request.on('error', (error) => {
                resolve(null);
            });

            request.setTimeout(5000, () => {
                request.destroy();
                resolve(null);
            });

            request.end();
        });
    } catch (error) {
        return null;
    }
};

const actionHandlers = {
    register: async ({ username, password }, user) => {
        const banCheck = await moderationSystem.checkBan(username);
        if (banCheck.banned) {
            return { error: "banned", reason: banCheck.reason };
        }

        if (typeof username !== "string" || typeof password !== "string") {
            return { error: "bad input" };
        }

        if (!storage.validateUsername(username.trim())) {
            return { error: "invalid username format" };
        }

        try {
            const result = await storage.registerUser(username.trim(), password.trim());
            if (result) {
                await notificationService.sendWelcomeNotification(username.trim());
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

        const banCheck = await moderationSystem.checkBan(username);
        if (banCheck.banned) {
            return { error: "banned", reason: banCheck.reason };
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

        if (config.redis?.enabled && redisService) {
            redisService.invalidateUserChannels(user).catch(err => {});
        }

        return { success: true, channelId, channel: name.trim() };
    },

    getChannels: async (data, user) => {
        if (!user) {
            return { error: "not auth" };
        }

        if (config.redis?.enabled && redisService) {
            try {
                const cached = await redisService.getCachedUserChannels(user);
                if (cached) {
                    return { success: true, channels: cached };
                }
            } catch (error) {}
        }

        const channels = await storage.getChannels(user);
        
        if (config.redis?.enabled && redisService) {
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

        if (config.redis?.enabled && redisService) {
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

        if (config.redis?.enabled && redisService) {
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

        if (config.redis?.enabled && redisService) {
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

        if (config.redis?.enabled && redisService) {
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
        
        if (config.redis?.enabled && redisService) {
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
                const anse2 = moduleLoader.get('anse2');
                if (anse2 && anse2.anse2_encrypt_wasm) {
                    const encoder = new TextEncoder();
                    const inputBytes = encoder.encode(processedText);
                    const encryptedBytes = anse2.anse2_encrypt_wasm(inputBytes, config.security.encryptionKey);
                    processedText = Buffer.from(encryptedBytes).toString('base64');
                    isEncrypted = true;
                }
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
                const anse2 = moduleLoader.get('anse2');
                if (anse2 && anse2.anse2_decrypt_wasm) {
                    const encryptedBytes = Buffer.from(saved.text, 'base64');
                    const decryptedBytes = anse2.anse2_decrypt_wasm(encryptedBytes, config.security.encryptionKey);
                    const decoder = new TextDecoder();
                    saved.text = decoder.decode(decryptedBytes);
                    saved.encrypted = false;
                }
            } catch (error) {
                saved.text = "[encrypted message]";
            }
        }
        
        const messageToSend = {
            ...saved,
            type: "message",
            action: "new"
        };

        if (wss && wss.broadcast) {
            wss.broadcast(messageToSend);
        }

        sseClients.forEach(client => {
            if (client.user === user) {
                client.res.write(`data: ${JSON.stringify(messageToSend)}\n\n`);
            }
        });

        if (botSystem && botSystem.processMessageForBots) {
            await botSystem.processMessageForBots(saved);
        }

        if (notificationService && notificationService.onNewMessage) {
            await notificationService.onNewMessage(saved);
        }

        if (config.redis?.enabled && redisService) {
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

        if (wss && wss.broadcast) {
            wss.broadcast(messageToSend);
        }

        sseClients.forEach(client => {
            if (client.user === user) {
                client.res.write(`data: ${JSON.stringify(messageToSend)}\n\n`);
            }
        });

        if (botSystem && botSystem.processMessageForBots) {
            await botSystem.processMessageForBots(saved);
        }

        if (notificationService && notificationService.onNewMessage) {
            await notificationService.onNewMessage(saved);
        }

        if (config.redis?.enabled && redisService) {
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

        const offerData = {
            type: "webrtc-offer",
            from: user,
            offer: offer,
            channel: channel
        };

        if (wss && wss.broadcast) {
            wss.broadcast(offerData);
        }

        return { success: true };
    },

    webrtcAnswer: async ({ toUser, answer }, user) => {
        if (!user || !toUser || !answer) {
            return { error: "missing answer data" };
        }

        await storage.saveWebRTCAnswer(user, toUser, answer);

        const answerData = {
            type: "webrtc-answer",
            from: user,
            answer: answer
        };

        if (wss && wss.broadcast) {
            wss.broadcast(answerData);
        }

        return { success: true };
    },

    iceCandidate: async ({ toUser, candidate }, user) => {
        if (!user || !toUser || !candidate) {
            return { error: "missing candidate data" };
        }

        await storage.saveICECandidate(user, toUser, candidate);

        const candidateData = {
            type: "webrtc-ice-candidate",
            from: user,
            candidate: candidate
        };

        if (wss && wss.broadcast) {
            wss.broadcast(candidateData);
        }

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

        const endCallData = {
            type: "webrtc-end-call",
            from: user
        };

        if (wss && wss.broadcast) {
            wss.broadcast(endCallData);
        }

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

        if (EmailService && EmailService.sendPasswordResetEmail) {
            await EmailService.sendPasswordResetEmail(email, resetToken);
        }

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

        let sent = false;
        if (EmailService && EmailService.sendVerificationEmail) {
            sent = await EmailService.sendVerificationEmail(email, verificationCode);
        }
        
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
    },

    banUser: async ({ username, durationMs, reason }, user) => {
        if (!user || user !== 'admin') {
            return { error: "unauthorized" };
        }

        const result = await moderationSystem.banUser(username, durationMs, reason, user);
        return { success: true, result };
    },

    unbanUser: async ({ username }, user) => {
        if (!user || user !== 'admin') {
            return { error: "unauthorized" };
        }

        const result = await moderationSystem.unbanUser(username, user);
        return { success: true, result };
    },

    warnUser: async ({ username, reason }, user) => {
        if (!user || user !== 'admin') {
            return { error: "unauthorized" };
        }

        const result = await moderationSystem.warnUser(username, reason, user);
        return { success: true, result };
    },

    getBot: async ({ username }, user) => {
        if (!user) {
            return { error: "not auth" };
        }

        const bots = botSystem.getUserBots(user);
        const bot = bots.find(b => b.username === username);
        return { success: true, bot };
    },

    createBot: async ({ username, webhookUrl }, user) => {
        if (!user) {
            return { error: "not auth" };
        }

        try {
            const bot = await botSystem.registerBot(username, user, webhookUrl);
            return { success: true, bot };
        } catch (error) {
            return { error: error.message };
        }
    },

    deleteBot: async ({ username }, user) => {
        if (!user) {
            return { error: "not auth" };
        }

        try {
            const result = await botSystem.deleteBot(username, user);
            return { success: true, result };
        } catch (error) {
            return { error: error.message };
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
            logger.error('Endpoint', `Error in ${path}: ${e.message}`);
            res.status(500).json({ success: false, error: "server error" });
        }
    });
};

if (notificationManager && notificationManager.middleware) {
    app.use(notificationManager.middleware());
}

if (notificationManager && notificationManager.setupRoutes) {
    notificationManager.setupRoutes(app);
}

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

        const extension = path.extname(user.avatar).toLowerCase();
        let mimeType = 'image/jpeg';
        if (extension === '.png') mimeType = 'image/png';
        else if (extension === '.gif') mimeType = 'image/gif';
        else if (extension === '.webp') mimeType = 'image/webp';
        else if (extension === '.jpg' || extension === '.jpeg') mimeType = 'image/jpeg';

        res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
        res.setHeader('Pragma', 'no-cache');
        res.setHeader('Expires', '0');
        res.setHeader('Content-Type', mimeType);

        res.sendFile(user.avatar, { root: config.uploads.dir });
    } catch (error) {
        logger.error('AvatarRoute', `Error serving avatar: ${error.message}`);
        res.status(500).json({ success: false, error: "server error" });
    }
});

if (globalRateLimiter && globalRateLimiter.middleware) {
    app.use(globalRateLimiter.middleware());
}

if (firewall && firewall.middleware) {
    app.use(firewall.middleware());
}

createEndpoint('post', '/api/register', [], 'register');
createEndpoint('post', '/api/login', [], 'login');
createEndpoint('post', '/api/2fa/verify-login', [], 'verify2FALogin');
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
createEndpoint('post', '/api/auth/reset-password', [], 'requestPasswordReset');
createEndpoint('post', '/api/auth/reset-password/confirm', [], 'resetPassword');
createEndpoint('post', '/api/admin/ban', require2FAMiddleware, 'banUser');
createEndpoint('post', '/api/admin/unban', require2FAMiddleware, 'unbanUser');
createEndpoint('post', '/api/admin/warn', require2FAMiddleware, 'warnUser');
createEndpoint('post', '/api/bots/create', require2FAMiddleware, 'createBot');
createEndpoint('get', '/api/bots/:username', require2FAMiddleware, 'getBot');
createEndpoint('delete', '/api/bots/:username', require2FAMiddleware, 'deleteBot');

app.post("/api/dcp/initiate", require2FAMiddleware, async (req, res) => {
    try {
        const { target, channel, callType = 'audio', metadata = {} } = req.body;
        
        if (!target) {
            return res.status(400).json({ success: false, error: "Target user required" });
        }

        const targetOnline = dcp && dcp.isUserOnline ? dcp.isUserOnline(target) : false;
        if (!targetOnline) {
            return res.status(404).json({ success: false, error: "Target user is offline" });
        }

        const userInCall = dcp && dcp.isUserInCall ? dcp.isUserInCall(req.user) : false;
        if (userInCall) {
            return res.status(400).json({ success: false, error: "You are already in a call" });
        }

        return res.json({ 
            success: true, 
            message: "Use WebSocket connection for DCP calls",
            protocol: "dcp",
            supported: true
        });
    } catch (error) {
        logger.error('DCP', `Initiate call error: ${error.message}`);
        res.status(500).json({ success: false, error: "server error" });
    }
});

app.get("/api/dcp/call/:callId", require2FAMiddleware, async (req, res) => {
    try {
        const callId = req.params.callId;
        const callInfo = dcp && dcp.getCallInfo ? dcp.getCallInfo(callId) : null;
        
        if (!callInfo) {
            return res.status(404).json({ success: false, error: "Call not found" });
        }

        if (!callInfo.participants.includes(req.user)) {
            return res.status(403).json({ success: false, error: "Not authorized to view this call" });
        }

        res.json({
            success: true,
            call: {
                id: callInfo.id,
                caller: callInfo.caller,
                target: callInfo.target,
                channel: callInfo.channel,
                type: callInfo.type,
                status: callInfo.status,
                participants: callInfo.participants,
                createdAt: callInfo.createdAt,
                lastActivity: callInfo.lastActivity,
                duration: Date.now() - callInfo.createdAt
            }
        });
    } catch (error) {
        logger.error('DCP', `Get call info error: ${error.message}`);
        res.status(500).json({ success: false, error: "server error" });
    }
});

app.get("/api/dcp/user/calls", require2FAMiddleware, async (req, res) => {
    try {
        const userCalls = dcp && dcp.getUserCalls ? dcp.getUserCalls(req.user) : [];
        res.json({
            success: true,
            calls: userCalls.map(call => ({
                id: call.id,
                caller: call.caller,
                target: call.target,
                channel: call.channel,
                type: call.type,
                status: call.status,
                participants: call.participants,
                createdAt: call.createdAt,
                duration: Date.now() - call.createdAt
            }))
        });
    } catch (error) {
        logger.error('DCP', `Get user calls error: ${error.message}`);
        res.status(500).json({ success: false, error: "server error" });
    }
});

app.post("/api/dcp/end/:callId", require2FAMiddleware, async (req, res) => {
    try {
        const callId = req.params.callId;
        const callInfo = dcp && dcp.getCallInfo ? dcp.getCallInfo(callId) : null;
        
        if (!callInfo) {
            return res.status(404).json({ success: false, error: "Call not found" });
        }

        if (!callInfo.participants.includes(req.user)) {
            return res.status(403).json({ success: false, error: "Not a participant in this call" });
        }

        return res.json({
            success: true,
            message: "Use WebSocket to end call",
            callId
        });
    } catch (error) {
        logger.error('DCP', `End call error: ${error.message}`);
        res.status(500).json({ success: false, error: "server error" });
    }
});

app.get("/api/dcp/stats", require2FAMiddleware, async (req, res) => {
    try {
        const stats = {
            activeCalls: dcp && dcp.activeCalls ? dcp.activeCalls.size : 0,
            connectedUsers: dcp && dcp.userConnections ? dcp.userConnections.size : 0,
            protocol: "DCP v1.0",
            features: ["audio", "video", "keep-alive", "session-management"]
        };
        
        res.json({ success: true, stats });
    } catch (error) {
        logger.error('DCP', `Get stats error: ${error.message}`);
        res.status(500).json({ success: false, error: "server error" });
    }
});

app.get("/api/ping", (req, res) => {
    res.json({ success: true, message: "pong", timestamp: Date.now() });
});

app.get("/api/admin/redis-stats", require2FAMiddleware, async (req, res) => {
    try {
        if (!redisService || !redisService.getStats) {
            return res.status(503).json({ success: false, error: "Redis service not available" });
        }
        const stats = await redisService.getStats();
        res.json({ success: true, stats });
    } catch (error) {
        logger.error('Redis', `Get stats error: ${error.message}`);
        res.status(500).json({ success: false, error: "Failed to get Redis stats" });
    }
});

app.post("/api/upload/avatar", require2FAMiddleware, avatarUpload.single("avatar"), async (req, res) => {
    try {
        const result = await actionHandlers.uploadAvatar(req, req.user);
        res.json(result);
    } catch (error) {
        logger.error('Upload', `Avatar upload error: ${error.message}`);
        res.status(500).json({ success: false, error: "upload failed" });
    }
});

app.post("/api/upload/file", require2FAMiddleware, fileUpload.single("file"), async (req, res) => {
    try {
        const result = await actionHandlers.uploadFile(req, req.user);
        res.json(result);
    } catch (error) {
        logger.error('Upload', `File upload error: ${error.message}`);
        res.status(500).json({ success: false, error: "upload failed" });
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
        logger.error('Upload', `Voice upload error: ${error.message}`);
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
        const extension = path.extname(filename).toLowerCase();
        let mimeType = 'application/octet-stream';
        
        if (extension === '.ogg') mimeType = 'audio/ogg';
        else if (extension === '.m4a' || extension === '.mp4') mimeType = 'audio/mp4';
        else if (extension === '.mp3') mimeType = 'audio/mpeg';
        else if (extension === '.wav') mimeType = 'audio/wav';
        
        const originalName = storage.getOriginalFileName ? storage.getOriginalFileName(filename) : filename;
        
        res.setHeader('Content-Type', mimeType);
        res.setHeader('Content-Disposition', `attachment; filename="${encodeURIComponent(originalName)}"`);
        res.sendFile(path.resolve(filePath));
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
        logger.debug('SSE', `Client disconnected: ${client.id}`);
    });

    res.write(`data: ${JSON.stringify({ type: "connected", clientId: client.id })}\n\n`);
    logger.debug('SSE', `New SSE client connected: ${client.id} (user: ${req.user})`);
});

app.get("/api/dcp/online/:username", require2FAMiddleware, async (req, res) => {
    try {
        const target = req.params.username;
        const isOnline = dcp && dcp.isUserOnline ? dcp.isUserOnline(target) : false;
        
        res.json({
            success: true,
            username: target,
            isOnline: isOnline,
            lastSeen: isOnline ? 'online' : 'offline',
            timestamp: Date.now()
        });
    } catch (error) {
        logger.error('DCP', `Online status error: ${error.message}`);
        res.status(500).json({ success: false, error: "server error" });
    }
});

let wss = null;
if (WebSocketServer) {
    wss = new WebSocketServer({ noServer: true });
} else {
    logger.warn('Server', 'WebSocketServer not available');
    wss = {
        broadcast: () => {},
        handleUpgrade: () => {},
        on: () => {}
    };
}

let dcp = null;
if (DCPProtocol && wss) {
    dcp = new DCPProtocol(wss, {
        keepAliveInterval: 30000,
        sessionTimeout: 300000,
        maxParticipants: 10
    });
} else {
    logger.warn('Server', 'DCP Protocol not available');
    dcp = {
        isUserOnline: () => false,
        isUserInCall: () => false,
        getCallInfo: () => null,
        getUserCalls: () => [],
        activeCalls: { size: 0 },
        userConnections: { size: 0 },
        cleanup: () => {},
        on: () => {}
    };
}

if (dcp && dcp.on) {
    dcp.on('call_ended', (data) => {
        logger.info('DCP', `Call ended: ${data.callId}, reason: ${data.reason}`);
        
        const callInfo = dcp.getCallInfo ? dcp.getCallInfo(data.callId) : null;
        if (callInfo) {
            callInfo.participants.forEach(participant => {
                sseClients.forEach(client => {
                    if (client.user === participant) {
                        client.res.write(`data: ${JSON.stringify({
                            type: "call_ended",
                            callId: data.callId,
                            reason: data.reason,
                            endedBy: data.endedBy,
                            timestamp: Date.now()
                        })}\n\n`);
                    }
                });
            });
        }
    });

    dcp.on('call_incoming', (data) => {
        logger.info('DCP', `Incoming call to ${data.target} from ${data.caller}`);
        
        sseClients.forEach(client => {
            if (client.user === data.target) {
                client.res.write(`data: ${JSON.stringify({
                    type: "dcp_call_incoming",
                    callId: data.callId,
                    caller: data.caller,
                    callType: data.callType,
                    channel: data.channel,
                    timestamp: Date.now()
                })}\n\n`);
            }
        });
    });
}

if (wss && wss.on) {
    wss.on("connection", (ws, req) => {
        wsClients.add(ws);
        ws.isAlive = true;

        ws.on("pong", () => { ws.isAlive = true; });
        ws.on("close", () => {
            wsClients.delete(ws);
            logger.debug('WebSocket', `Client disconnected: ${ws.user}`);
        });

        ws.on("message", async data => {
            try {
                const payload = JSON.parse(data.toString());
                
                const dcpMessageTypes = [
                    'call_initiate', 'call_accept', 'call_reject', 'call_end',
                    'sdp_offer', 'sdp_answer', 'ice_candidate', 'keep_alive',
                    'call_status', 'mute_audio', 'mute_video'
                ];
                
                if (payload.type && (payload.type.startsWith('dcp_') || dcpMessageTypes.includes(payload.type))) {
                    return;
                }
                
                const result = await actionHandlers[payload.action]?.(payload, ws.user);
                if (result) ws.send(JSON.stringify(result));
            } catch (e) {
                logger.error('WebSocket', `Message error: ${e.message}`);
            }
        });
        
        logger.debug('WebSocket', `New WebSocket connection: ${ws.user}`);
    });
}

const server = app.listen(config.server.port, config.server.host, () => {
    const address = server.address();
    logger.info('Server', `Started on ${address.address}:${address.port}`);
    logger.info('Server', `ModuleLoader initialized`);
});

if (server && wss && wss.handleUpgrade) {
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
                if (wss.emit) {
                    wss.emit("connection", ws, req);
                }
            });
        }).catch(err => {
            logger.error('WebSocket', `Upgrade error: ${err.message}`);
            socket.destroy();
        });
    });
}

if (dcp) {
    dcp.isUserOnline = (username) => {
        return dcp.userConnections ? dcp.userConnections.has(username) : false;
    };
}

if (notificationService) {
    notificationService.wss = wss;
    notificationService.sse = { 
        clients: sseClients,
        sendToUser: (userId, data) => {
            sseClients.forEach(client => {
                if (client.user === userId) {
                    client.res.write(`data: ${JSON.stringify(data)}\n\n`);
                }
            });
        }
    };
}

if (botSystem) {
    botSystem.wss = wss;
}

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
            logger.debug('2FA', `Expired session cleaned up for user: ${username}`);
        }
    }

    if (now % 3600000 < 30000) {
        if (storage.cleanupOldVoiceMessages) {
            storage.cleanupOldVoiceMessages(24 * 60 * 60).catch(error => {
                logger.error('Maintenance', `Voice message cleanup error: ${error.message}`);
            });
        }
    }

    if (dcp && dcp.cleanup) {
        dcp.cleanup();
    }
}, 30000);

process.on("SIGTERM", async () => {
    logger.info('Server', 'Received SIGTERM, shutting down gracefully...');
    clearInterval(interval);
    
    if (dcp && dcp.cleanup) {
        dcp.cleanup();
    }
    
    if (proxyManager && proxyManager.cleanup) {
        proxyManager.cleanup();
    }
    
    if (moduleLoader && moduleLoader.cleanup) {
        await moduleLoader.cleanup();
    }
    
    server.close(() => {
        logger.info('Server', 'Server shutdown complete');
        process.exit(0);
    });
});

export { dcp, moduleLoader, wss, sseClients, wsClients };
export default app;
