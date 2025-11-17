import fs from "fs";
import crypto from "crypto";
import path from "path";
import config from "../../config.js";

let db = { 
  users: [], 
  messages: [], 
  tokens: [], 
  channels: [], 
  channelMembers: [],
  webrtcOffers: [],
  webrtcAnswers: [],
  iceCandidates: [],
  twoFactorSecrets: [],
  voiceMessages: [],
  files: [],
  emailVerifications: [],
  passwordResets: [],
  bans: [],
  pushSubscriptions: [],
  notifications: [],
  channelSubscriptions: []
};
const file = config.storage.file;

function atomicWrite(path, data) {
  const tmp = path + ".tmp";
  fs.writeFileSync(tmp, data);
  fs.renameSync(tmp, path);
}

function load() {
  if (fs.existsSync(file)) {
    try {
      const raw = fs.readFileSync(file, "utf8");
      const parsed = JSON.parse(raw);
      if (parsed && typeof parsed === "object") db = parsed;
    } catch {}
  }
}

function save() {
  const data = JSON.stringify(db, null, 2);
  atomicWrite(file, data);
}

function pbkdf2(password, salt) {
  return crypto.pbkdf2Sync(
    password,
    salt,
    config.security.pbkdf2.iterations,
    config.security.pbkdf2.keylen,
    config.security.pbkdf2.digest
  ).toString("hex");
}

function sha256(str) {
  return crypto.createHash("sha256").update(str).digest("hex");
}

export function registerUser(username, passwordPlain) {
  if (db.users.find(u => u.username === username)) return false;
  const salt = crypto.randomBytes(16).toString("hex");
  const passwordHash = pbkdf2(passwordPlain, salt);
  db.users.push({ username, passwordHash, salt, avatar: null, twoFactorEnabled: false, type: 'user' });
  save();
  return true;
}

export function authenticate(username, passwordPlain) {
  const u = db.users.find(u => u.username === username);
  if (!u) return null;
  if (u.salt) {
    const check = pbkdf2(passwordPlain, u.salt);
    return check === u.passwordHash ? u.username : null;
  } else {
    const check = sha256(passwordPlain);
    return check === u.passwordHash ? u.username : null;
  }
}

export function saveToken(username, token, expires) {
  db.tokens = db.tokens.filter(t => t.expires > Date.now());
  db.tokens.push({ username, token, expires });
  save();
}

export function validateToken(token) {
  db.tokens = db.tokens.filter(t => t.expires > Date.now());
  const t = db.tokens.find(t => t.token === token);
  return Promise.resolve(t ? t.username : null);
}

export function saveMessage(msg) {
  msg.id = crypto.randomBytes(16).toString("hex");
  db.messages.push(msg);
  save();
  return msg;
}

export function getMessages(channel, limit, before) {
  let msgs = db.messages.filter(m => m.channel === channel);
  if (before) msgs = msgs.filter(m => m.ts < before);
  msgs.sort((a, b) => b.ts - a.ts);
  return msgs.slice(0, limit).reverse();
}

export function createChannel(channelName, creator, customId = null) {
  const channelId = customId || sha256(channelName + Date.now());
  
  if (db.channels.find(c => c.id === channelId || c.name === channelName)) return false;
  
  db.channels.push({ 
    id: channelId, 
    name: channelName, 
    creator, 
    createdAt: Date.now(),
    customId: !!customId
  });
  
  joinChannel(channelId, creator);
  return channelId;
}

export function getChannels(username) {
  return db.channels.filter(c => 
    db.channelMembers.some(cm => cm.channel === c.id && cm.username === username)
  );
}

export function updateChannelName(oldName, newName, username) {
  const channel = db.channels.find(c => c.name === oldName);
  if (!channel) return false;
  if (channel.creator !== username) return false;
  if (db.channels.find(c => c.name === newName)) return false;
  channel.name = newName;
  db.channelMembers.forEach(cm => {
    if (cm.channel === channel.id) cm.channel = channel.id;
  });
  db.messages.forEach(m => {
    if (m.channel === oldName) m.channel = newName;
  });
  save();
  return true;
}

export function searchChannels(query) {
  if (query === "" || query === "%") {
    return db.channels;
  }
  return db.channels.filter(c => 
    c.name.toLowerCase().includes(query.toLowerCase())
  );
}

export function joinChannel(channel, username) {
  const channelObj = db.channels.find(c => c.id === channel || c.name === channel);
  if (!channelObj) return false;
  if (db.channelMembers.find(cm => cm.channel === channelObj.id && cm.username === username)) return true;
  db.channelMembers.push({ channel: channelObj.id, username, joinedAt: Date.now() });
  save();
  return true;
}

export function leaveChannel(channel, username) {
  const channelObj = db.channels.find(c => c.id === channel || c.name === channel);
  if (!channelObj) return false;
  const index = db.channelMembers.findIndex(cm => cm.channel === channelObj.id && cm.username === username);
  if (index === -1) return false;
  db.channelMembers.splice(index, 1);
  save();
  return true;
}

export function getChannelMembers(channel) {
  const channelObj = db.channels.find(c => c.id === channel || c.name === channel);
  if (!channelObj) return [];
  return db.channelMembers.filter(cm => cm.channel === channelObj.id).map(cm => cm.username);
}

export function isChannelMember(channel, username) {
  const channelObj = db.channels.find(c => c.id === channel || c.name === channel);
  if (!channelObj) return false;
  return db.channelMembers.some(cm => cm.channel === channelObj.id && cm.username === username);
}

export function saveWebRTCOffer(fromUser, toUser, offer, channel) {
  db.webrtcOffers = db.webrtcOffers.filter(o => o.timestamp > Date.now() - 300000);
  db.webrtcOffers.push({ fromUser, toUser, offer, channel, timestamp: Date.now() });
  save();
}

export function getWebRTCOffer(fromUser, toUser) {
  const offer = db.webrtcOffers.find(o => o.fromUser === fromUser && o.toUser === toUser);
  if (offer && offer.timestamp > Date.now() - 300000) {
    return offer;
  }
  return null;
}

export function saveWebRTCAnswer(fromUser, toUser, answer) {
  db.webrtcAnswers = db.webrtcAnswers.filter(a => a.timestamp > Date.now() - 300000);
  db.webrtcAnswers.push({ fromUser, toUser, answer, timestamp: Date.now() });
  save();
}

export function getWebRTCAnswer(fromUser, toUser) {
  const answer = db.webrtcAnswers.find(a => a.fromUser === fromUser && a.toUser === toUser);
  if (answer && answer.timestamp > Date.now() - 300000) {
    return answer;
  }
  return null;
}

export function saveICECandidate(fromUser, toUser, candidate) {
  db.iceCandidates = db.iceCandidates.filter(c => c.timestamp > Date.now() - 300000);
  db.iceCandidates.push({ fromUser, toUser, candidate, timestamp: Date.now() });
  save();
}

export function getICECandidates(fromUser, toUser) {
  const candidates = db.iceCandidates.filter(c => c.fromUser === fromUser && c.toUser === toUser);
  const validCandidates = candidates.filter(c => c.timestamp > Date.now() - 300000);
  return validCandidates.map(c => c.candidate);
}

export function updateUserAvatar(username, avatarFilename) {
  const user = db.users.find(u => u.username === username);
  if (!user) return false;
  user.avatar = avatarFilename;
  save();
  return true;
}

export function getUsers() {
  return db.users.map(u => ({ username: u.username, avatar: u.avatar }));
}

export function isTwoFactorEnabled(username) {
  const user = db.users.find(u => u.username === username);
  return user ? user.twoFactorEnabled : false;
}

export function getTwoFactorSecret(username) {
  const secret = db.twoFactorSecrets.find(s => s.username === username);
  return secret ? secret.secret : null;
}

export function setTwoFactorSecret(username, secret) {
  const existing = db.twoFactorSecrets.findIndex(s => s.username === username);
  if (existing !== -1) {
    db.twoFactorSecrets[existing].secret = secret;
  } else {
    db.twoFactorSecrets.push({ username, secret });
  }
  save();
}

export function enableTwoFactor(username, enabled) {
  const user = db.users.find(u => u.username === username);
  if (!user) return false;
  user.twoFactorEnabled = enabled;
  save();
  return true;
}

export function saveVoiceMessageInfo(voiceId, username, channel, duration) {
  db.voiceMessages.push({
    voiceId,
    username,
    channel,
    duration,
    timestamp: Date.now()
  });
  save();
}

export function getVoiceMessageDuration(voiceId) {
  const voiceMsg = db.voiceMessages.find(v => v.voiceId === voiceId);
  return voiceMsg ? voiceMsg.duration : 0;
}

export async function cleanupOldVoiceMessages(maxAgeSeconds = 86400) {
  const cutoff = Date.now() - (maxAgeSeconds * 1000);
  const initialLength = db.voiceMessages.length;
  db.voiceMessages = db.voiceMessages.filter(v => v.timestamp > cutoff);
  
  if (db.voiceMessages.length !== initialLength) {
    save();
  }
  
  return initialLength - db.voiceMessages.length;
}

export function saveFileInfo(fileInfo) {
  db.files.push(fileInfo);
  save();
}

export function getFileInfo(fileId) {
  return db.files.find(f => f.id === fileId) || null;
}

export function getOriginalFileName(filename) {
  const file = db.files.find(f => f.filename === filename);
  return file ? file.originalName : filename;
}

export function getMessageById(messageId) {
  return db.messages.find(m => m.id === messageId) || null;
}

export function setUserEmail(username, email) {
  const user = db.users.find(u => u.username === username);
  if (!user) return false;
  user.email = email;
  user.emailVerified = true;
  save();
  return true;
}

export function getUserByEmail(email) {
  const user = db.users.find(u => u.email === email);
  return user ? user.username : null;
}

export function createEmailVerification(username, email, code) {
  db.emailVerifications = db.emailVerifications.filter(v => v.expires > Date.now());
  db.emailVerifications.push({
    username,
    email,
    code,
    expires: Date.now() + 24 * 60 * 60 * 1000
  });
  save();
  return true;
}

export function verifyEmailCode(username, email, code) {
  const verification = db.emailVerifications.find(v => 
    v.username === username && v.email === email && v.code === code && v.expires > Date.now()
  );
  if (verification) {
    db.emailVerifications = db.emailVerifications.filter(v => v !== verification);
    save();
    return true;
  }
  return false;
}

export function createPasswordReset(username, token) {
  db.passwordResets = db.passwordResets.filter(r => r.expires > Date.now());
  db.passwordResets.push({
    username,
    token,
    expires: Date.now() + 60 * 60 * 1000
  });
  save();
  return true;
}

export function usePasswordReset(token, newPassword) {
  const reset = db.passwordResets.find(r => r.token === token && r.expires > Date.now());
  if (!reset) return false;

  const user = db.users.find(u => u.username === reset.username);
  if (!user) return false;

  const salt = crypto.randomBytes(16).toString("hex");
  const passwordHash = pbkdf2(newPassword, salt);
  user.passwordHash = passwordHash;
  user.salt = salt;

  db.passwordResets = db.passwordResets.filter(r => r !== reset);
  save();
  return true;
}

export function setUserType(username, type) {
  const user = db.users.find(u => u.username === username);
  if (!user) return false;
  user.type = type;
  save();
  return true;
}

export function saveBan(banInfo) {
  db.bans = db.bans.filter(b => b.expires > Date.now());
  const existingIndex = db.bans.findIndex(b => b.username === banInfo.username);
  if (existingIndex !== -1) {
    db.bans[existingIndex] = banInfo;
  } else {
    db.bans.push(banInfo);
  }
  save();
  return true;
}

export function getBan(username) {
  db.bans = db.bans.filter(b => b.expires > Date.now());
  return db.bans.find(b => b.username === username) || null;
}

export function removeBan(username) {
  const initialLength = db.bans.length;
  db.bans = db.bans.filter(b => b.username !== username);
  if (db.bans.length !== initialLength) {
    save();
    return true;
  }
  return false;
}

export function savePushSubscription(userId, subscription) {
  if (!db.pushSubscriptions.find(s => s.userId === userId && s.id === subscription.id)) {
    db.pushSubscriptions.push({
      userId,
      ...subscription
    });
    save();
  }
  return Promise.resolve();
}

export function deletePushSubscription(userId, subscriptionId) {
  const initialLength = db.pushSubscriptions.length;
  db.pushSubscriptions = db.pushSubscriptions.filter(s => 
    !(s.userId === userId && s.id === subscriptionId)
  );
  if (db.pushSubscriptions.length !== initialLength) {
    save();
  }
  return Promise.resolve();
}

export function getPushSubscriptions(userId) {
  return Promise.resolve(db.pushSubscriptions.filter(s => s.userId === userId));
}

export function saveNotification(notification) {
  if (!db.notifications.find(n => n.id === notification.id)) {
    db.notifications.push(notification);
    save();
  }
  return Promise.resolve();
}

export function markNotificationAsRead(userId, notificationId) {
  const notification = db.notifications.find(n => 
    n.userId === userId && n.id === notificationId
  );
  if (notification) {
    notification.read = true;
    save();
  }
  return Promise.resolve();
}

export function markAllNotificationsAsRead(userId) {
  db.notifications.forEach(n => {
    if (n.userId === userId) {
      n.read = true;
    }
  });
  save();
  return Promise.resolve();
}

export function getUserNotifications(userId, options = {}) {
  const { limit = 50, offset = 0, unreadOnly = false, types = [] } = options;
  
  let notifications = db.notifications.filter(n => n.userId === userId);
  
  if (unreadOnly) {
    notifications = notifications.filter(n => !n.read);
  }
  
  if (types.length > 0) {
    notifications = notifications.filter(n => types.includes(n.type));
  }
  
  notifications.sort((a, b) => b.timestamp - a.timestamp);
  
  return Promise.resolve(notifications.slice(offset, offset + limit));
}

export function getUnreadNotificationCount(userId) {
  const count = db.notifications.filter(n => 
    n.userId === userId && !n.read
  ).length;
  return Promise.resolve(count);
}

export function deleteNotification(userId, notificationId) {
  const initialLength = db.notifications.length;
  db.notifications = db.notifications.filter(n => 
    !(n.userId === userId && n.id === notificationId)
  );
  if (db.notifications.length !== initialLength) {
    save();
  }
  return Promise.resolve();
}

export function cleanupExpiredSubscriptions(userId, currentTime) {
  const initialLength = db.pushSubscriptions.length;
  db.pushSubscriptions = db.pushSubscriptions.filter(s => 
    s.userId !== userId || s.expires > currentTime
  );
  if (db.pushSubscriptions.length !== initialLength) {
    save();
  }
  return Promise.resolve();
}

export function cleanupExpiredNotifications() {
  const currentTime = Date.now();
  const initialLength = db.notifications.length;
  db.notifications = db.notifications.filter(n => n.expires > currentTime);
  if (db.notifications.length !== initialLength) {
    save();
  }
  return Promise.resolve();
}

export function saveChannelSubscription(userId, channelId, types) {
  const existingIndex = db.channelSubscriptions.findIndex(cs => 
    cs.userId === userId && cs.channelId === channelId
  );
  
  if (existingIndex !== -1) {
    db.channelSubscriptions[existingIndex].types = types;
  } else {
    db.channelSubscriptions.push({
      userId,
      channelId,
      types
    });
  }
  save();
  return Promise.resolve();
}

export function deleteChannelSubscription(userId, channelId) {
  const initialLength = db.channelSubscriptions.length;
  db.channelSubscriptions = db.channelSubscriptions.filter(cs => 
    !(cs.userId === userId && cs.channelId === channelId)
  );
  if (db.channelSubscriptions.length !== initialLength) {
    save();
  }
  return Promise.resolve();
}

export function getUserChannelSubscriptions(userId) {
  return Promise.resolve(
    db.channelSubscriptions.filter(cs => cs.userId === userId)
  );
}

load();
setInterval(save, 30000);
