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
  twoFactorSecrets: []
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
  db.users.push({ username, passwordHash, salt, avatar: null, twoFactorEnabled: false });
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
  return t ? t.username : null;
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

export function createChannel(channelName, creator) {
  if (db.channels.find(c => c.name === channelName)) return false;
  db.channels.push({ name: channelName, creator, createdAt: Date.now() });
  joinChannel(channelName, creator);
  return true;
}

export function getChannels(username) {
  return db.channels.filter(c => 
    db.channelMembers.some(cm => cm.channel === c.name && cm.username === username)
  );
}

export function joinChannel(channel, username) {
  if (!db.channels.find(c => c.name === channel)) return false;
  if (db.channelMembers.find(cm => cm.channel === channel && cm.username === username)) return true;
  db.channelMembers.push({ channel, username, joinedAt: Date.now() });
  save();
  return true;
}

export function leaveChannel(channel, username) {
  const index = db.channelMembers.findIndex(cm => cm.channel === channel && cm.username === username);
  if (index === -1) return false;
  db.channelMembers.splice(index, 1);
  save();
  return true;
}

export function getChannelMembers(channel) {
  return db.channelMembers.filter(cm => cm.channel === channel).map(cm => cm.username);
}

export function isChannelMember(channel, username) {
  return db.channelMembers.some(cm => cm.channel === channel && cm.username === username);
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

load();
setInterval(save, 30000);
