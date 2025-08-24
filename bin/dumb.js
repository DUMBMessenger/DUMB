#!/usr/bin/env node
import fs from "fs";
import path from "path";
import inquirer from "inquirer";
import gradient from "gradient-string";
import { fileURLToPath } from "url";
import { execSync } from "child_process";
import process from "process";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

async function clearConsole() {
  process.stdout.write("\x1Bc");
}

function copyTemplate(filename, targetDir) {
  const src = path.join(__dirname, "../templates", filename);
  const dest = path.join(targetDir, filename);
  fs.copyFileSync(src, dest);
}

async function askQuestions() {
  const questions = [
    {
      type: "list",
      name: "db",
      message: "Select database (where messenger data will be stored):",
      choices: ["json", "sqlite", "mysql"],
      default: "json"
    },
    {
      type: "list",
      name: "ws",
      message: "Enable WebSocket (for real-time and VoIP signaling)?",
      choices: ["enable", "disable"],
      default: "enable"
    },
    {
      type: "list",
      name: "sse",
      message: "Enable Server-Sent Events (lightweight one-way streaming)?",
      choices: ["enable", "disable"],
      default: "disable"
    },
    {
      type: "list",
      name: "voip",
      message: "Enable VoIP (WebRTC signaling)?",
      choices: ["enable", "disable"],
      default: "disable"
    },
    {
      type: "list",
      name: "uploads",
      message: "Enable file uploads (files, avatars)?",
      choices: ["enable", "disable"],
      default: "enable"
    },
    {
      type: "input",
      name: "port",
      message: "Server port (where it will listen):",
      default: "3000",
      validate: input => /^\d+$/.test(input) ? true : "Please enter a valid port number"
    }
  ];

  return inquirer.prompt(questions);
}

async function runInstaller() {
  clearConsole();
  console.log(gradient("sliver", "magenta").multiline([
     "DUMB Installer v2"
  ]));

  let answers;
  try {
    answers = await askQuestions();
  } catch (err) {
    console.error("❌ Prompt failed:", err);
    process.exit(1);
  }

  const config = {
    server: {
      host: "0.0.0.0",
      port: parseInt(answers.port, 10),
      protocols: {
        http: true,
        websocket: answers.ws === "enable",
        sse: answers.sse === "enable"
      }
    },
    db: answers.db,
    features: {
      ws: answers.ws === "enable",
      sse: answers.sse === "enable",
      voip: answers.voip === "enable",
      uploads: answers.uploads === "enable"
    },
    client: {
      web: {
        enabled: false,
        sourceUrl: "",
        targetDir: "public"
      }
    }
  };

  const projectPath = path.join(process.cwd(), "DUMB");
  if (!fs.existsSync(projectPath)) fs.mkdirSync(projectPath);

  const templatesDir = path.join(projectPath, "templates");
  if (!fs.existsSync(templatesDir)) fs.mkdirSync(templatesDir, { recursive: true });

  const slavesDir = path.join(projectPath, "storage", "slaves");
  if (!fs.existsSync(slavesDir)) fs.mkdirSync(slavesDir, { recursive: true });

  ["server.js", "storage.js", "config.js"].forEach(file => copyTemplate(file, projectPath));
  
  const jsonSlavePath = path.join(slavesDir, "json.js");
  const sqlsSlavePath = path.join(slavesDir, "sqls.js");
  
  fs.writeFileSync(jsonSlavePath, `import fs from "fs";
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

load();`);

  fs.writeFileSync(sqlsSlavePath, `import fs from "fs";
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

await init();`);

  const cfgFile = path.join(projectPath, "config.js");
  fs.writeFileSync(cfgFile, `export default {
  server: {
    host: "0.0.0.0",
    port: ${parseInt(answers.port, 10)}
  },
  features: {
    http: true,
    ws: ${answers.ws === "enable"},
    sse: ${answers.sse === "enable"},
    voip: ${answers.voip === "enable"},
    uploads: ${answers.uploads === "enable"}
  },
  security: {
    passwordMinLength: 8,
    tokenTTL: 24 * 60 * 60 * 1000,
    pbkdf2: {
      iterations: 120000,
      keylen: 32,
      digest: "sha256"
    },
    maxMessageLength: 2000
  },
  storage: {
    type: "${answers.db}",
    file: "db.json"
  },
  uploads: {
    dir: "uploads",
    maxFileSize: 2 * 1024 * 1024,
    allowedMime: ["image/png", "image/jpeg", "image/webp", "image/gif"]
  },
  cors: {
    origin: "*"
  },
  rateLimit: {
    windowMs: 60 * 1000,
    max: 60
  }
}`);

  const pkg = {
    name: "dumb-server",
    version: "2.0.0",
    type: "module",
    scripts: { start: "node server.js" },
    dependencies: {
      express: "^4.18.2",
      ws: "^8.17.0",
     "sql.js": "^1.9.0",
      mysql2: "^3.9.7",
      multer: "1.4.4",
      cors: "^2.8.5",
      inquirer: "^8.2.4",
      "gradient-string": "^2.0.2"
    }
  };
  fs.writeFileSync(path.join(projectPath, "package.json"), JSON.stringify(pkg, null, 2));

  console.log("\n📦 Installing dependencies...\n");
  try {
    execSync("npm install", { cwd: projectPath, stdio: "inherit" });
  } catch (err) {
    console.error("❌ npm install failed:", err);
    process.exit(1);
  }

  console.log("\n✅ Setup complete!\n  cd DUMB && npm start\n");
}

runInstaller();
