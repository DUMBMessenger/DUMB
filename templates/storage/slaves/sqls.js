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
    db.run("CREATE TABLE IF NOT EXISTS messages (id INTEGER PRIMARY KEY AUTOINCREMENT, channel TEXT, fromUser TEXT, text TEXT, ts INTEGER)");
  } else if (sqlMode === "mysql") {
    mysqlConn = await mysql.createConnection(config.storage.mysql);
    await mysqlConn.execute("CREATE TABLE IF NOT EXISTS users (username VARCHAR(255) PRIMARY KEY, passwordHash TEXT, salt TEXT)");
    await mysqlConn.execute("CREATE TABLE IF NOT EXISTS tokens (username VARCHAR(255), token TEXT, expiry BIGINT)");
    await mysqlConn.execute("CREATE TABLE IF NOT EXISTS messages (id BIGINT AUTO_INCREMENT PRIMARY KEY, channel VARCHAR(255), fromUser VARCHAR(255), text TEXT, ts BIGINT)");
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
  if (sqlMode === "sqlite") {
    db.run("INSERT INTO messages (channel,fromUser,text,ts) VALUES (?,?,?,?)", [msg.channel, msg.from, msg.text, msg.ts]);
    persist();
    return msg;
  } else {
    await mysqlConn.execute("INSERT INTO messages (channel,fromUser,text,ts) VALUES (?,?,?,?)", [msg.channel, msg.from, msg.text, msg.ts]);
    return msg;
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

await init();
