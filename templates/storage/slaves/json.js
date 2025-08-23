import fs from "fs";
import crypto from "crypto";
import config from "../../config.js";

let db = { users: [], messages: [], tokens: [] };
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
  db.users.push({ username, passwordHash, salt });
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
  db.messages.push(msg);
  if (db.messages.length > 100000) db.messages = db.messages.slice(-50000);
  save();
  return msg;
}

export function getMessages(channel, limit = 100, beforeTs = null) {
  let arr = db.messages.filter(m => m.channel === channel);
  if (beforeTs) arr = arr.filter(m => m.ts < beforeTs);
  arr.sort((a, b) => a.ts - b.ts);
  if (limit && limit > 0) arr = arr.slice(-limit);
  return arr;
}

load();
