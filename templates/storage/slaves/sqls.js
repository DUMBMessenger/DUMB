import fs from "fs";
import initSqlJs from "sql.js";
import mysql from "mysql2/promise";
import crypto from "crypto";
import config from "../../config.js";

let db;
let dbFile = config.storage.sqlite;
let sqlMode = config.storage.type;
let mysqlConn;

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

async function init() {
  if (sqlMode === "sqlite") {
    const SQL = await initSqlJs();
    if (fs.existsSync(dbFile)) {
      const filebuffer = fs.readFileSync(dbFile);
      db = new SQL.Database(filebuffer);
    } else {
      db = new SQL.Database();
    }
    db.run("CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, passwordHash TEXT, salt TEXT)");
    db.run("CREATE TABLE IF NOT EXISTS tokens (username TEXT, token TEXT, expiry INTEGER)");
    db.run("CREATE TABLE IF NOT EXISTS messages (id TEXT PRIMARY KEY, channel TEXT, fromUser TEXT, text TEXT, ts INTEGER, replyTo TEXT)");
    db.run("CREATE TABLE IF NOT EXISTS channels (name TEXT PRIMARY KEY, createdBy TEXT, createdAt INTEGER)");
    db.run("CREATE TABLE IF NOT EXISTS channel_members (channel TEXT, username TEXT, joinedAt INTEGER, PRIMARY KEY(channel, username))");
    db.run("CREATE TABLE IF NOT EXISTS webrtc_offers (id INTEGER PRIMARY KEY AUTOINCREMENT, fromUser TEXT, toUser TEXT, offer TEXT, channel TEXT, timestamp INTEGER)");
    db.run("CREATE TABLE IF NOT EXISTS webrtc_answers (id INTEGER PRIMARY KEY AUTOINCREMENT, fromUser TEXT, toUser TEXT, answer TEXT, timestamp INTEGER)");
    db.run("CREATE TABLE IF NOT EXISTS ice_candidates (id INTEGER PRIMARY KEY AUTOINCREMENT, fromUser TEXT, toUser TEXT, candidate TEXT, timestamp INTEGER)");
  } else if (sqlMode === "mysql") {
    mysqlConn = await mysql.createConnection(config.storage.mysql);
    await mysqlConn.execute("CREATE TABLE IF NOT EXISTS users (username VARCHAR(255) PRIMARY KEY, passwordHash TEXT, salt TEXT)");
    await mysqlConn.execute("CREATE TABLE IF NOT EXISTS tokens (username VARCHAR(255), token TEXT, expiry BIGINT)");
    await mysqlConn.execute("CREATE TABLE IF NOT EXISTS messages (id VARCHAR(255) PRIMARY KEY, channel VARCHAR(255), fromUser VARCHAR(255), text TEXT, ts BIGINT, replyTo VARCHAR(255))");
    await mysqlConn.execute("CREATE TABLE IF NOT EXISTS channels (name VARCHAR(255) PRIMARY KEY, createdBy VARCHAR(255), createdAt BIGINT)");
    await mysqlConn.execute("CREATE TABLE IF NOT EXISTS channel_members (channel VARCHAR(255), username VARCHAR(255), joinedAt BIGINT, PRIMARY KEY(channel, username))");
    await mysqlConn.execute("CREATE TABLE IF NOT EXISTS webrtc_offers (id BIGINT AUTO_INCREMENT PRIMARY KEY, fromUser VARCHAR(255), toUser VARCHAR(255), offer TEXT, channel VARCHAR(255), timestamp BIGINT)");
    await mysqlConn.execute("CREATE TABLE IF NOT EXISTS webrtc_answers (id BIGINT AUTO_INCREMENT PRIMARY KEY, fromUser VARCHAR(255), toUser VARCHAR(255), answer TEXT, timestamp BIGINT)");
    await mysqlConn.execute("CREATE TABLE IF NOT EXISTS ice_candidates (id BIGINT AUTO_INCREMENT PRIMARY KEY, fromUser VARCHAR(255), toUser VARCHAR(255), candidate TEXT, timestamp BIGINT)");
  }
}

function persist() {
  if (sqlMode === "sqlite") {
    const data = db.export();
    fs.writeFileSync(dbFile, Buffer.from(data));
  }
}

export async function registerUser(username, passwordPlain) {
  const salt = crypto.randomBytes(16).toString("hex");
  const passwordHash = pbkdf2(passwordPlain, salt);
  if (sqlMode === "sqlite") {
    const stmt = db.prepare("SELECT 1 FROM users WHERE username=?");
    const exists = stmt.getAsObject([username]);
    stmt.free();
    if (exists.username) return false;
    db.run("INSERT INTO users (username,passwordHash,salt) VALUES (?,?,?)", [username, passwordHash, salt]);
    persist();
    return true;
  } else {
    const [rows] = await mysqlConn.execute("SELECT 1 FROM users WHERE username=?", [username]);
    if (rows.length) return false;
    await mysqlConn.execute("INSERT INTO users (username,passwordHash,salt) VALUES (?,?,?)", [username, passwordHash, salt]);
    return true;
  }
}

export async function authenticate(username, passwordPlain) {
  if (sqlMode === "sqlite") {
    const stmt = db.prepare("SELECT * FROM users WHERE username=?");
    const row = stmt.getAsObject([username]);
    stmt.free();
    if (!row.username) return null;
    if (row.salt) {
      const check = pbkdf2(passwordPlain, row.salt);
      return check === row.passwordHash ? row : null;
    } else {
      const legacy = sha256(passwordPlain);
      return legacy === row.passwordHash ? row : null;
    }
  } else {
    const [rows] = await mysqlConn.execute("SELECT * FROM users WHERE username=?", [username]);
    if (!rows.length) return null;
    const u = rows[0];
    if (u.salt) {
      const check = pbkdf2(passwordPlain, u.salt);
      return check === u.passwordHash ? u : null;
    } else {
      const legacy = sha256(passwordPlain);
      return legacy === u.passwordHash ? u : null;
    }
  }
}

export async function saveToken(username, token, expiry) {
  if (sqlMode === "sqlite") {
    db.run("DELETE FROM tokens WHERE username=?", [username]);
    db.run("INSERT INTO tokens (username,token,expiry) VALUES (?,?,?)", [username, token, expiry]);
    persist();
  } else {
    await mysqlConn.execute("DELETE FROM tokens WHERE username=?", [username]);
    await mysqlConn.execute("INSERT INTO tokens (username,token,expiry) VALUES (?,?,?)", [username, token, expiry]);
  }
}

export async function validateToken(token) {
  const now = Date.now();
  if (sqlMode === "sqlite") {
    db.run("DELETE FROM tokens WHERE expiry <= ?", [now]);
    const stmt = db.prepare("SELECT username FROM tokens WHERE token=?");
    const row = stmt.getAsObject([token]);
    stmt.free();
    return row.username || null;
  } else {
    await mysqlConn.execute("DELETE FROM tokens WHERE expiry <= ?", [now]);
    const [rows] = await mysqlConn.execute("SELECT username FROM tokens WHERE token=?", [token]);
    return rows.length ? rows[0].username : null;
  }
}

export async function saveMessage(msg) {
  const messageId = crypto.randomBytes(16).toString("hex");
  const messageWithId = { ...msg, id: messageId };
  
  if (sqlMode === "sqlite") {
    db.run("INSERT INTO messages (id, channel, fromUser, text, ts, replyTo) VALUES (?,?,?,?,?,?)", 
      [messageId, msg.channel, msg.from, msg.text, msg.ts, msg.replyTo || null]);
    persist();
    return messageWithId;
  } else {
    await mysqlConn.execute("INSERT INTO messages (id, channel, fromUser, text, ts, replyTo) VALUES (?,?,?,?,?,?)", 
      [messageId, msg.channel, msg.from, msg.text, msg.ts, msg.replyTo || null]);
    return messageWithId;
  }
}

export async function getMessages(channel, limit = 100, beforeTs = null) {
  if (sqlMode === "sqlite") {
    let query = "SELECT * FROM messages WHERE channel=? ";
    let params = [channel];
    if (beforeTs) {
      query += "AND ts < ? ";
      params.push(beforeTs);
    }
    query += "ORDER BY ts ASC LIMIT ?";
    params.push(limit);
    const stmt = db.prepare(query);
    const rows = [];
    stmt.bind(params);
    while (stmt.step()) rows.push(stmt.getAsObject());
    stmt.free();
    return rows;
  } else {
    let query = "SELECT * FROM messages WHERE channel=? ";
    let params = [channel];
    if (beforeTs) {
      query += "AND ts < ? ";
      params.push(beforeTs);
    }
    query += "ORDER BY ts ASC LIMIT ?";
    params.push(limit);
    const [rows] = await mysqlConn.execute(query, params);
    return rows;
  }
}

export async function createChannel(channelName, creator) {
  if (sqlMode === "sqlite") {
    const stmt = db.prepare("SELECT 1 FROM channels WHERE name=?");
    const exists = stmt.getAsObject([channelName]);
    stmt.free();
    if (exists.name) return false;
    
    db.run("INSERT INTO channels (name, createdBy, createdAt) VALUES (?, ?, ?)", [channelName, creator, Date.now()]);
    await joinChannel(channelName, creator);
    persist();
    return true;
  } else {
    const [rows] = await mysqlConn.execute("SELECT 1 FROM channels WHERE name=?", [channelName]);
    if (rows.length) return false;
    
    await mysqlConn.execute("INSERT INTO channels (name, createdBy, createdAt) VALUES (?, ?, ?)", [channelName, creator, Date.now()]);
    await joinChannel(channelName, creator);
    return true;
  }
}

export async function getChannels(username) {
  if (sqlMode === "sqlite") {
    const query = `
      SELECT c.name FROM channels c
      JOIN channel_members cm ON c.name = cm.channel
      WHERE cm.username = ?
    `;
    const stmt = db.prepare(query);
    stmt.bind([username]);
    const rows = [];
    while (stmt.step()) rows.push(stmt.getAsObject().name);
    stmt.free();
    return rows;
  } else {
    const [rows] = await mysqlConn.execute(`
      SELECT c.name FROM channels c
      JOIN channel_members cm ON c.name = cm.channel
      WHERE cm.username = ?
    `, [username]);
    return rows.map(row => row.name);
  }
}

export async function joinChannel(channelName, username) {
  if (sqlMode === "sqlite") {
    const stmt = db.prepare("SELECT 1 FROM channels WHERE name=?");
    const exists = stmt.getAsObject([channelName]);
    stmt.free();
    if (!exists.name) return false;
    
    db.run("INSERT OR IGNORE INTO channel_members (channel, username, joinedAt) VALUES (?, ?, ?)", [channelName, username, Date.now()]);
    persist();
    return true;
  } else {
    const [rows] = await mysqlConn.execute("SELECT 1 FROM channels WHERE name=?", [channelName]);
    if (!rows.length) return false;
    
    await mysqlConn.execute("INSERT IGNORE INTO channel_members (channel, username, joinedAt) VALUES (?, ?, ?)", [channelName, username, Date.now()]);
    return true;
  }
}

export async function leaveChannel(channelName, username) {
  if (sqlMode === "sqlite") {
    db.run("DELETE FROM channel_members WHERE channel=? AND username=?", [channelName, username]);
    persist();
    return db.getRowsModified() > 0;
  } else {
    const [result] = await mysqlConn.execute("DELETE FROM channel_members WHERE channel=? AND username=?", [channelName, username]);
    return result.affectedRows > 0;
  }
}

export async function getChannelMembers(channelName) {
  if (sqlMode === "sqlite") {
    const stmt = db.prepare("SELECT username FROM channel_members WHERE channel=?");
    stmt.bind([channelName]);
    const rows = [];
    while (stmt.step()) rows.push(stmt.getAsObject().username);
    stmt.free();
    return rows;
  } else {
    const [rows] = await mysqlConn.execute("SELECT username FROM channel_members WHERE channel=?", [channelName]);
    return rows.map(row => row.username);
  }
}

export async function isChannelMember(channelName, username) {
  if (sqlMode === "sqlite") {
    const stmt = db.prepare("SELECT 1 FROM channel_members WHERE channel=? AND username=?");
    const exists = stmt.getAsObject([channelName, username]);
    stmt.free();
    return !!exists.channel;
  } else {
    const [rows] = await mysqlConn.execute("SELECT 1 FROM channel_members WHERE channel=? AND username=?", [channelName, username]);
    return rows.length > 0;
  }
}

export async function saveWebRTCOffer(fromUser, toUser, offer, channel) {
  if (sqlMode === "sqlite") {
    db.run("DELETE FROM webrtc_offers WHERE fromUser=? AND toUser=?", [fromUser, toUser]);
    db.run("INSERT INTO webrtc_offers (fromUser, toUser, offer, channel, timestamp) VALUES (?, ?, ?, ?, ?)", 
      [fromUser, toUser, offer, channel, Date.now()]);
    persist();
    return true;
  } else {
    await mysqlConn.execute("DELETE FROM webrtc_offers WHERE fromUser=? AND toUser=?", [fromUser, toUser]);
    await mysqlConn.execute("INSERT INTO webrtc_offers (fromUser, toUser, offer, channel, timestamp) VALUES (?, ?, ?, ?, ?)", 
      [fromUser, toUser, offer, channel, Date.now()]);
    return true;
  }
}

export async function getWebRTCOffer(fromUser, toUser) {
  if (sqlMode === "sqlite") {
    const stmt = db.prepare("SELECT * FROM webrtc_offers WHERE fromUser=? AND toUser=? ORDER BY timestamp DESC LIMIT 1");
    const row = stmt.getAsObject([fromUser, toUser]);
    stmt.free();
    return row.fromUser ? row : null;
  } else {
    const [rows] = await mysqlConn.execute("SELECT * FROM webrtc_offers WHERE fromUser=? AND toUser=? ORDER BY timestamp DESC LIMIT 1", [fromUser, toUser]);
    return rows.length ? rows[0] : null;
  }
}

export async function saveWebRTCAnswer(fromUser, toUser, answer) {
  if (sqlMode === "sqlite") {
    db.run("DELETE FROM webrtc_answers WHERE fromUser=? AND toUser=?", [fromUser, toUser]);
    db.run("INSERT INTO webrtc_answers (fromUser, toUser, answer, timestamp) VALUES (?, ?, ?, ?)", 
      [fromUser, toUser, answer, Date.now()]);
    persist();
    return true;
  } else {
    await mysqlConn.execute("DELETE FROM webrtc_answers WHERE fromUser=? AND toUser=?", [fromUser, toUser]);
    await mysqlConn.execute("INSERT INTO webrtc_answers (fromUser, toUser, answer, timestamp) VALUES (?, ?, ?, ?)", 
      [fromUser, toUser, answer, Date.now()]);
    return true;
  }
}

export async function getWebRTCAnswer(fromUser, toUser) {
  if (sqlMode === "sqlite") {
    const stmt = db.prepare("SELECT * FROM webrtc_answers WHERE fromUser=? AND toUser=? ORDER BY timestamp DESC LIMIT 1");
    const row = stmt.getAsObject([fromUser, toUser]);
    stmt.free();
    return row.fromUser ? row : null;
  } else {
    const [rows] = await mysqlConn.execute("SELECT * FROM webrtc_answers WHERE fromUser=? AND toUser=? ORDER BY timestamp DESC LIMIT 1", [fromUser, toUser]);
    return rows.length ? rows[0] : null;
  }
}

export async function saveICECandidate(fromUser, toUser, candidate) {
  if (sqlMode === "sqlite") {
    db.run("INSERT INTO ice_candidates (fromUser, toUser, candidate, timestamp) VALUES (?, ?, ?, ?)", 
      [fromUser, toUser, candidate, Date.now()]);
    persist();
    return true;
  } else {
    await mysqlConn.execute("INSERT INTO ice_candidates (fromUser, toUser, candidate, timestamp) VALUES (?, ?, ?, ?)", 
      [fromUser, toUser, candidate, Date.now()]);
    return true;
  }
}

export async function getICECandidates(fromUser, toUser) {
  if (sqlMode === "sqlite") {
    const stmt = db.prepare("SELECT * FROM ice_candidates WHERE fromUser=? AND toUser=? ORDER BY timestamp ASC");
    stmt.bind([fromUser, toUser]);
    const rows = [];
    while (stmt.step()) rows.push(stmt.getAsObject());
    stmt.free();
    return rows;
  } else {
    const [rows] = await mysqlConn.execute("SELECT * FROM ice_candidates WHERE fromUser=? AND toUser=? ORDER BY timestamp ASC", [fromUser, toUser]);
    return rows;
  }
}

await init();
