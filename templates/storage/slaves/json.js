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
  iceCandidates: []
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
  db.users.push({ username, passwordHash, salt, avatar: null });
  save();
  return true;
}

export function authenticate(username, passwordPlain) {
  const u = db.users.find(u => u.username === username);
  if (!u) return null;
  if (u.salt) {
    const check = pbkdf2(passwordPlain, u.salt);
    return check === u.passwordHash ? u : null;
  } else {
    const legacy = sha256(passwordPlain);
    return legacy === u.passwordHash ? u : null;
  }
}

export function saveToken(username, token, expiry) {
  db.tokens = db.tokens.filter(t => t.username !== username);
  db.tokens.push({ username, token, expiry });
  save();
}

export function validateToken(token) {
  const now = Date.now();
  db.tokens = db.tokens.filter(t => t.expiry > now);
  const t = db.tokens.find(t => t.token === token);
  return t ? t.username : null;
}

export function saveMessage(msg) {
  const messageWithId = {
    ...msg,
    id: crypto.randomBytes(16).toString("hex")
  };
  db.messages.push(messageWithId);
  if (db.messages.length > 100000) db.messages = db.messages.slice(-50000);
  save();
  return messageWithId;
}

export function getMessages(channel, limit = 100, beforeTs = null) {
  let arr = db.messages.filter(m => m.channel === channel);
  if (beforeTs) arr = arr.filter(m => m.ts < beforeTs);
  arr.sort((a, b) => a.ts - b.ts);
  if (limit && limit > 0) arr = arr.slice(-limit);
  return arr;
}

export function createChannel(channelName, creator) {
  if (db.channels.find(c => c.name === channelName)) return false;
  db.channels.push({ name: channelName, createdBy: creator, createdAt: Date.now() });
  joinChannel(channelName, creator);
  save();
  return true;
}

export function getChannels(username) {
  const userChannels = db.channelMembers
    .filter(cm => cm.username === username)
    .map(cm => db.channels.find(c => c.name === cm.channel))
    .filter(c => c);
  
  return userChannels.map(c => c.name);
}

export function joinChannel(channelName, username) {
  const channel = db.channels.find(c => c.name === channelName);
  if (!channel) return false;
  
  const existing = db.channelMembers.find(cm => cm.channel === channelName && cm.username === username);
  if (!existing) {
    db.channelMembers.push({ channel: channelName, username, joinedAt: Date.now() });
    save();
  }
  return true;
}

export function leaveChannel(channelName, username) {
  const index = db.channelMembers.findIndex(cm => cm.channel === channelName && cm.username === username);
  if (index === -1) return false;
  
  db.channelMembers.splice(index, 1);
  save();
  return true;
}

export function getChannelMembers(channelName) {
  return db.channelMembers
    .filter(cm => cm.channel === channelName)
    .map(cm => cm.username);
}

export function isChannelMember(channelName, username) {
  return db.channelMembers.some(cm => cm.channel === channelName && cm.username === username);
}

export function saveWebRTCOffer(fromUser, toUser, offer, channel) {
  db.webrtcOffers = db.webrtcOffers.filter(o => 
    !(o.fromUser === fromUser && o.toUser === toUser)
  );
  
  db.webrtcOffers.push({
    fromUser,
    toUser,
    offer,
    channel,
    timestamp: Date.now()
  });
  save();
  return true;
}

export function getWebRTCOffer(fromUser, toUser) {
  const offer = db.webrtcOffers.find(o => 
    o.fromUser === fromUser && o.toUser === toUser
  );
  return offer || null;
}

export function saveWebRTCAnswer(fromUser, toUser, answer) {
  db.webrtcAnswers = db.webrtcAnswers.filter(a => 
    !(a.fromUser === fromUser && a.toUser === toUser)
  );
  
  db.webrtcAnswers.push({
    fromUser,
    toUser,
    answer,
    timestamp: Date.now()
  });
  save();
  return true;
}

export function getWebRTCAnswer(fromUser, toUser) {
  const answer = db.webrtcAnswers.find(a => 
    a.fromUser === fromUser && a.toUser === toUser
  );
  return answer || null;
}

export function saveICECandidate(fromUser, toUser, candidate) {
  db.iceCandidates.push({
    fromUser,
    toUser,
    candidate,
    timestamp: Date.now()
  });
  save();
  return true;
}

export function getICECandidates(fromUser, toUser) {
  return db.iceCandidates.filter(c => 
    c.fromUser === fromUser && c.toUser === toUser
  );
}

export function updateUserAvatar(username, avatarFilename) {
  const user = db.users.find(u => u.username === username);
  if (!user) return false;
  
  if (user.avatar) {
    const oldAvatarPath = path.join(config.uploads.dir, user.avatar);
    if (fs.existsSync(oldAvatarPath)) {
      fs.unlinkSync(oldAvatarPath);
    }
  }
  
  user.avatar = avatarFilename;
  save();
  return true;
}

export function getUsers() {
  return db.users;
}

load();
