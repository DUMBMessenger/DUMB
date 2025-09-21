import config from "../../config.js";
import path from "path";
import crypto from "crypto";

let db;
let pool;

async function initDatabase() {
  if (config.storage.type === "sqlite") {
    const initSqlJs = await import("sql.js");
    const fs = await import("fs");

    let databaseData;
    const dbPath = path.resolve(config.storage.file);

    try {
      if (fs.existsSync(dbPath)) {
        databaseData = new Uint8Array(fs.readFileSync(dbPath));
      }
    } catch (error) {
      console.warn("Could not read existing database file, creating new one");
    }

    const SQL = await initSqlJs.default();
    db = new SQL.Database(databaseData);
    await createTables();

    const saveDb = () => {
      try {
        const data = db.export();
        fs.writeFileSync(dbPath, Buffer.from(data));
      } catch (error) {
        console.error("Failed to save database:", error);
      }
    };

    setInterval(saveDb, 30000);
    process.on("exit", saveDb);

  } else if (config.storage.type === "mysql") {
    const mysql = await import("mysql2/promise");

    pool = mysql.createPool({
      host: config.storage.host,
      port: config.storage.port,
      user: config.storage.user,
      password: config.storage.password,
      database: config.storage.database,
      connectionLimit: 10,
      acquireTimeout: 60000,
      timeout: 60000,
      reconnect: true,
    });

    await createTables();
  }
}

async function createTables() {
  const tables = [
    `CREATE TABLE IF NOT EXISTS users (
      username VARCHAR(255) PRIMARY KEY,
      password_hash VARCHAR(255) NOT NULL,
      salt VARCHAR(255),
      avatar VARCHAR(255),
      two_factor_enabled BOOLEAN DEFAULT FALSE,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )`,
    `CREATE TABLE IF NOT EXISTS tokens (
      token VARCHAR(255) PRIMARY KEY,
      username VARCHAR(255) NOT NULL,
      expires BIGINT NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (username) REFERENCES users(username) ON DELETE CASCADE
    )`,
    `CREATE TABLE IF NOT EXISTS channels (
      id VARCHAR(255) PRIMARY KEY,
      name VARCHAR(255) NOT NULL UNIQUE,
      creator VARCHAR(255) NOT NULL,
      custom_id BOOLEAN DEFAULT FALSE,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (creator) REFERENCES users(username) ON DELETE CASCADE
    )`,
    `CREATE TABLE IF NOT EXISTS channel_members (
      channel VARCHAR(255) NOT NULL,
      username VARCHAR(255) NOT NULL,
      joined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      PRIMARY KEY (channel, username),
      FOREIGN KEY (channel) REFERENCES channels(id) ON DELETE CASCADE,
      FOREIGN KEY (username) REFERENCES users(username) ON DELETE CASCADE
    )`,
    `CREATE TABLE IF NOT EXISTS messages (
      id VARCHAR(255) PRIMARY KEY,
      channel VARCHAR(255) NOT NULL,
      from_user VARCHAR(255) NOT NULL,
      text TEXT NOT NULL,
      ts BIGINT NOT NULL,
      reply_to VARCHAR(255),
      file_attachment TEXT,
      voice_attachment TEXT,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (channel) REFERENCES channels(id) ON DELETE CASCADE,
      FOREIGN KEY (from_user) REFERENCES users(username) ON DELETE CASCADE
    )`,
    `CREATE TABLE IF NOT EXISTS webrtc_offers (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      from_user VARCHAR(255) NOT NULL,
      to_user VARCHAR(255) NOT NULL,
      offer TEXT NOT NULL,
      channel VARCHAR(255),
      timestamp BIGINT NOT NULL,
      FOREIGN KEY (from_user) REFERENCES users(username) ON DELETE CASCADE,
      FOREIGN KEY (to_user) REFERENCES users(username) ON DELETE CASCADE
    )`,
    `CREATE TABLE IF NOT EXISTS webrtc_answers (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      from_user VARCHAR(255) NOT NULL,
      to_user VARCHAR(255) NOT NULL,
      answer TEXT NOT NULL,
      timestamp BIGINT NOT NULL,
      FOREIGN KEY (from_user) REFERENCES users(username) ON DELETE CASCADE,
      FOREIGN KEY (to_user) REFERENCES users(username) ON DELETE CASCADE
    )`,
    `CREATE TABLE IF NOT EXISTS ice_candidates (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      from_user VARCHAR(255) NOT NULL,
      to_user VARCHAR(255) NOT NULL,
      candidate TEXT NOT NULL,
      timestamp BIGINT NOT NULL,
      FOREIGN KEY (from_user) REFERENCES users(username) ON DELETE CASCADE,
      FOREIGN KEY (to_user) REFERENCES users(username) ON DELETE CASCADE
    )`,
    `CREATE TABLE IF NOT EXISTS two_factor_secrets (
      username VARCHAR(255) PRIMARY KEY,
      secret VARCHAR(255),
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (username) REFERENCES users(username) ON DELETE CASCADE
    )`,
    `CREATE TABLE IF NOT EXISTS voice_messages (
      voice_id VARCHAR(255) PRIMARY KEY,
      username VARCHAR(255) NOT NULL,
      channel VARCHAR(255) NOT NULL,
      duration INTEGER NOT NULL,
      timestamp BIGINT NOT NULL,
      FOREIGN KEY (username) REFERENCES users(username) ON DELETE CASCADE,
      FOREIGN KEY (channel) REFERENCES channels(id) ON DELETE CASCADE
    )`,
    `CREATE TABLE IF NOT EXISTS files (
      id VARCHAR(255) PRIMARY KEY,
      filename VARCHAR(255) NOT NULL,
      original_name VARCHAR(255) NOT NULL,
      mimetype VARCHAR(255) NOT NULL,
      size INTEGER NOT NULL,
      uploaded_at BIGINT NOT NULL,
      uploaded_by VARCHAR(255) NOT NULL,
      FOREIGN KEY (uploaded_by) REFERENCES users(username) ON DELETE CASCADE
    )`
  ];

  if (config.storage.type === "sqlite") {
    for (const tableSql of tables) {
      db.run(tableSql);
    }
  } else if (config.storage.type === "mysql") {
    const connection = await pool.getConnection();
    try {
      for (const tableSql of tables) {
        await connection.execute(tableSql);
      }
    } finally {
      connection.release();
    }
  }
}

function pbkdf2(password, salt) {
  return crypto
    .pbkdf2Sync(
      password,
      salt,
      config.security.pbkdf2.iterations,
      config.security.pbkdf2.keylen,
      config.security.pbkdf2.digest
    )
    .toString("hex");
}

function sha256(str) {
  return crypto.createHash("sha256").update(str).digest("hex");
}

async function query(sql, params = []) {
  if (config.storage.type === "sqlite") {
    const stmt = db.prepare(sql);
    stmt.bind(params);
    const rows = [];
    while (stmt.step()) rows.push(stmt.getAsObject());
    const modified = db.getRowsModified();
    stmt.free();
    return { rows, affectedRows: modified };
  } else if (config.storage.type === "mysql") {
    const connection = await pool.getConnection();
    try {
      const [rows, fields] = await connection.execute(sql, params);
      return { rows, affectedRows: rows.affectedRows || rows.length || 0 };
    } finally {
      connection.release();
    }
  }
}

async function queryOne(sql, params = []) {
  const result = await query(sql, params);
  return result.rows[0] || null;
}

export async function registerUser(username, passwordPlain) {
  const existingUser = await queryOne("SELECT username FROM users WHERE username = ?", [username]);
  if (existingUser) return false;

  const salt = crypto.randomBytes(16).toString("hex");
  const passwordHash = pbkdf2(passwordPlain, salt);

  await query("INSERT INTO users (username, password_hash, salt) VALUES (?, ?, ?)", [
    username,
    passwordHash,
    salt,
  ]);

  return true;
}

export async function authenticate(username, passwordPlain) {
  const user = await queryOne("SELECT * FROM users WHERE username = ?", [username]);
  if (!user) return null;

  let isValid;
  if (user.salt) {
    const check = pbkdf2(passwordPlain, user.salt);
    isValid = check === user.password_hash;
  } else {
    const check = sha256(passwordPlain);
    isValid = check === user.password_hash;
  }

  return isValid ? username : null;
}

export async function saveToken(username, token, expires) {
  await query("DELETE FROM tokens WHERE expires < ?", [Date.now()]);

  if (config.storage.type === "sqlite") {
    await query(
      `INSERT INTO tokens (token, username, expires) VALUES (?, ?, ?) ON CONFLICT(token) DO UPDATE SET expires = excluded.expires`,
      [token, username, expires]
    );
  } else {
    await query(
      `INSERT INTO tokens (token, username, expires) VALUES (?, ?, ?) ON DUPLICATE KEY UPDATE expires = ?`,
      [token, username, expires, expires]
    );
  }

  return true;
}

export async function validateToken(token) {
  await query("DELETE FROM tokens WHERE expires < ?", [Date.now()]);
  const result = await queryOne("SELECT username FROM tokens WHERE token = ?", [token]);
  return result ? result.username : null;
}

export async function saveMessage(msg) {
  msg.id = crypto.randomBytes(16).toString("hex");
  await query(
    `INSERT INTO messages (id, channel, from_user, text, ts, reply_to, file_attachment, voice_attachment) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    [
      msg.id,
      msg.channel,
      msg.from,
      msg.text,
      msg.ts,
      msg.replyTo || null,
      msg.file ? JSON.stringify(msg.file) : null,
      msg.voice ? JSON.stringify(msg.voice) : null,
    ]
  );
  return msg;
}

export async function getMessages(channel, limit, before) {
  let sql = `SELECT * FROM messages WHERE channel = ?`;
  const params = [channel];
  if (before) {
    sql += " AND ts < ?";
    params.push(before);
  }
  sql += " ORDER BY ts DESC LIMIT ?";
  params.push(limit);

  const result = await query(sql, params);
  return result.rows
    .map((msg) => ({
      id: msg.id,
      from: msg.from_user,
      channel: msg.channel,
      text: msg.text,
      ts: msg.ts,
      replyTo: msg.reply_to,
      file: msg.file_attachment ? JSON.parse(msg.file_attachment) : null,
      voice: msg.voice_attachment ? JSON.parse(msg.voice_attachment) : null,
    }))
    .reverse();
}

export async function createChannel(channelName, creator, customId = null) {
  const channelId = customId || sha256(channelName + Date.now());
  
  try {
    await query("INSERT INTO channels (id, name, creator, custom_id) VALUES (?, ?, ?, ?)", 
      [channelId, channelName, creator, !!customId]);
    await joinChannel(channelId, creator);
    return channelId;
  } catch (error) {
    if (error.message.includes("UNIQUE constraint failed") || error.code === "ER_DUP_ENTRY") {
      return false;
    }
    throw error;
  }
}

export async function getChannels(username) {
  const result = await query(
    `SELECT c.* FROM channels c JOIN channel_members cm ON c.id = cm.channel WHERE cm.username = ?`,
    [username]
  );
  return result.rows;
}

export async function searchChannels(query) {
  const result = await query(
    `SELECT * FROM channels WHERE LOWER(name) LIKE LOWER(?)`,
    [`%${query}%`]
  );
  return result.rows;
}

export async function joinChannel(channel, username) {
  let channelId = channel;
  const channelByName = await queryOne("SELECT id FROM channels WHERE name = ?", [channel]);
  if (channelByName) {
    channelId = channelByName.id;
  } else {
    const channelById = await queryOne("SELECT id FROM channels WHERE id = ?", [channel]);
    if (!channelById) return false;
    channelId = channelById.id;
  }

  try {
    if (config.storage.type === "sqlite") {
      await query(
        `INSERT INTO channel_members (channel, username) VALUES (?, ?) ON CONFLICT(channel, username) DO UPDATE SET joined_at = CURRENT_TIMESTAMP`,
        [channelId, username]
      );
    } else {
      await query(
        `INSERT INTO channel_members (channel, username) VALUES (?, ?) ON DUPLICATE KEY UPDATE joined_at = CURRENT_TIMESTAMP`,
        [channelId, username]
      );
    }
    return true;
  } catch (error) {
    return false;
  }
}

export async function leaveChannel(channel, username) {
  let channelId = channel;
  const channelByName = await queryOne("SELECT id FROM channels WHERE name = ?", [channel]);
  if (channelByName) {
    channelId = channelByName.id;
  } else {
    const channelById = await queryOne("SELECT id FROM channels WHERE id = ?", [channel]);
    if (!channelById) return false;
    channelId = channelById.id;
  }

  const result = await query(
    "DELETE FROM channel_members WHERE channel = ? AND username = ?",
    [channelId, username]
  );
  return result.affectedRows > 0;
}

export async function getChannelMembers(channel) {
  let channelId = channel;
  const channelByName = await queryOne("SELECT id FROM channels WHERE name = ?", [channel]);
  if (channelByName) {
    channelId = channelByName.id;
  } else {
    const channelById = await queryOne("SELECT id FROM channels WHERE id = ?", [channel]);
    if (!channelById) return [];
    channelId = channelById.id;
  }

  const result = await query("SELECT username FROM channel_members WHERE channel = ?", [channelId]);
  return result.rows.map((m) => m.username);
}

export async function isChannelMember(channel, username) {
  let channelId = channel;
  const channelByName = await queryOne("SELECT id FROM channels WHERE name = ?", [channel]);
  if (channelByName) {
    channelId = channelByName.id;
  } else {
    const channelById = await queryOne("SELECT id FROM channels WHERE id = ?", [channel]);
    if (!channelById) return false;
    channelId = channelById.id;
  }

  const result = await queryOne(
    "SELECT 1 FROM channel_members WHERE channel = ? AND username = ?",
    [channelId, username]
  );
  return !!result;
}

export async function saveWebRTCOffer(fromUser, toUser, offer, channel) {
  await query("DELETE FROM webrtc_offers WHERE timestamp < ?", [Date.now() - 300000]);
  await query(
    "INSERT INTO webrtc_offers (from_user, to_user, offer, channel, timestamp) VALUES (?, ?, ?, ?, ?)",
    [fromUser, toUser, JSON.stringify(offer), channel, Date.now()]
  );
}

export async function getWebRTCOffer(fromUser, toUser) {
  await query("DELETE FROM webrtc_offers WHERE timestamp < ?", [Date.now() - 300000]);
  const result = await queryOne(
    "SELECT * FROM webrtc_offers WHERE from_user = ? AND to_user = ? ORDER BY timestamp DESC LIMIT 1",
    [fromUser, toUser]
  );
  if (!result) return null;
  return {
    fromUser: result.from_user,
    toUser: result.to_user,
    offer: JSON.parse(result.offer),
    channel: result.channel,
    timestamp: result.timestamp,
  };
}

export async function saveWebRTCAnswer(fromUser, toUser, answer) {
  await query("DELETE FROM webrtc_answers WHERE timestamp < ?", [Date.now() - 300000]);
  await query(
    "INSERT INTO webrtc_answers (from_user, to_user, answer, timestamp) VALUES (?, ?, ?, ?)",
    [fromUser, toUser, JSON.stringify(answer), Date.now()]
  );
}

export async function getWebRTCAnswer(fromUser, toUser) {
  await query("DELETE FROM webrtc_answers WHERE timestamp < ?", [Date.now() - 300000]);
  const result = await queryOne(
    "SELECT * FROM webrtc_answers WHERE from_user = ? AND to_user = ? ORDER BY timestamp DESC LIMit 1",
    [fromUser, toUser]
  );
  if (!result) return null;
  return {
    fromUser: result.from_user,
    toUser: result.to_user,
    answer: JSON.parse(result.answer),
    timestamp: result.timestamp,
  };
}

export async function saveICECandidate(fromUser, toUser, candidate) {
  await query("DELETE FROM ice_candidates WHERE timestamp < ?", [Date.now() - 300000]);
  await query(
    "INSERT INTO ice_candidates (from_user, to_user, candidate, timestamp) VALUES (?, ?, ?, ?)",
    [fromUser, toUser, JSON.stringify(candidate), Date.now()]
  );
}

export async function getICECandidates(fromUser, toUser) {
  await query("DELETE FROM ice_candidates WHERE timestamp < ?", [Date.now() - 300000]);
  const result = await query(
    "SELECT candidate FROM ice_candidates WHERE from_user = ? AND to_user = ? ORDER BY timestamp ASC",
    [fromUser, toUser]
  );
  return result.rows.map((c) => JSON.parse(c.candidate));
}

export async function updateUserAvatar(username, avatarFilename) {
  const result = await query("UPDATE users SET avatar = ? WHERE username = ?", [
    avatarFilename,
    username,
  ]);
  return result.affectedRows > 0;
}

export async function getUsers() {
  const result = await query("SELECT username, avatar FROM users");
  return result.rows;
}

export async function isTwoFactorEnabled(username) {
  const user = await queryOne("SELECT two_factor_enabled FROM users WHERE username = ?", [username]);
  return user ? user.two_factor_enabled : false;
}

export async function getTwoFactorSecret(username) {
  const secret = await queryOne("SELECT secret FROM two_factor_secrets WHERE username = ?", [
    username,
  ]);
  return secret ? secret.secret : null;
}

export async function setTwoFactorSecret(username, secret) {
  if (config.storage.type === "sqlite") {
    await query(
      `INSERT INTO two_factor_secrets (username, secret) VALUES (?, ?) ON CONFLICT(username) DO UPDATE SET secret = excluded.secret`,
      [username, secret]
    );
  } else {
    await query(
      `INSERT INTO two_factor_secrets (username, secret) VALUES (?, ?) ON DUPLICATE KEY UPDATE secret = ?`,
      [username, secret, secret]
    );
  }
}

export async function enableTwoFactor(username, enabled) {
  const result = await query("UPDATE users SET two_factor_enabled = ? WHERE username = ?", [
    enabled,
    username,
  ]);
  return result.affectedRows > 0;
}

export async function saveVoiceMessageInfo(voiceId, username, channel, duration) {
  await query(
    "INSERT INTO voice_messages (voice_id, username, channel, duration, timestamp) VALUES (?, ?, ?, ?, ?)",
    [voiceId, username, channel, duration, Date.now()]
  );
}

export async function getVoiceMessageDuration(voiceId) {
  const result = await queryOne(
    "SELECT duration FROM voice_messages WHERE voice_id = ?",
    [voiceId]
  );
  return result ? result.duration : 0;
}

export async function cleanupOldVoiceMessages(maxAgeSeconds = 86400) {
  const cutoff = Date.now() - (maxAgeSeconds * 1000);
  const result = await query(
    "DELETE FROM voice_messages WHERE timestamp < ?",
    [cutoff]
  );
  return result.affectedRows;
}

export async function saveFileInfo(fileInfo) {
  await query(
    "INSERT INTO files (id, filename, original_name, mimetype, size, uploaded_at, uploaded_by) VALUES (?, ?, ?, ?, ?, ?, ?)",
    [
      fileInfo.id,
      fileInfo.filename,
      fileInfo.originalName,
      fileInfo.mimetype,
      fileInfo.size,
      fileInfo.uploadedAt,
      fileInfo.uploadedBy
    ]
  );
}

export async function getFileInfo(fileId) {
  const result = await queryOne("SELECT * FROM files WHERE id = ?", [fileId]);
  if (!result) return null;
  
  return {
    id: result.id,
    filename: result.filename,
    originalName: result.original_name,
    mimetype: result.mimetype,
    size: result.size,
    uploadedAt: result.uploaded_at,
    uploadedBy: result.uploaded_by
  };
}

export async function getOriginalFileName(filename) {
  const result = await queryOne("SELECT original_name FROM files WHERE filename = ?", [filename]);
  return result ? result.original_name : filename;
}

initDatabase().catch((error) => {
  console.error("Failed to initialize database:", error);
  process.exit(1);
});
