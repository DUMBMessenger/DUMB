import sqlite3 from 'sql.js';
import mysql from 'mysql2/promise';
import crypto from 'crypto';
import config from '../../config.js';

let db;
let dbType;
let mysqlPool;

const initDatabase = async () => {
  dbType = config.storage.type || 'sqlite';

  if (dbType === 'mysql') {
    const mysqlConfig = config.storage.mysql;
    mysqlPool = mysql.createPool({
      host: mysqlConfig.host,
      port: mysqlConfig.port,
      user: mysqlConfig.user,
      password: mysqlConfig.password,
      database: mysqlConfig.database,
      connectionLimit: 10,
      acquireTimeout: 60000,
      timeout: 60000
    });

    await createMySQLTables();
  } else {
    const SQL = await sqlite3();
    db = new SQL.Database();
    createSQLiteTables();
  }
};

const createSQLiteTables = () => {
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      username TEXT PRIMARY KEY,
      passwordHash TEXT NOT NULL,
      salt TEXT NOT NULL,
      avatar TEXT,
      twoFactorEnabled BOOLEAN DEFAULT FALSE,
      email TEXT,
      emailVerified BOOLEAN DEFAULT FALSE,
      type TEXT DEFAULT 'user',
      createdAt DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS tokens (
      token TEXT PRIMARY KEY,
      username TEXT NOT NULL,
      expires BIGINT NOT NULL,
      FOREIGN KEY (username) REFERENCES users(username) ON DELETE CASCADE
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS channels (
      id TEXT PRIMARY KEY,
      name TEXT UNIQUE NOT NULL,
      creator TEXT NOT NULL,
      customId BOOLEAN DEFAULT FALSE,
      createdAt BIGINT NOT NULL,
      FOREIGN KEY (creator) REFERENCES users(username) ON DELETE CASCADE
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS channel_members (
      channel TEXT NOT NULL,
      username TEXT NOT NULL,
      joinedAt BIGINT NOT NULL,
      PRIMARY KEY (channel, username),
      FOREIGN KEY (channel) REFERENCES channels(id) ON DELETE CASCADE,
      FOREIGN KEY (username) REFERENCES users(username) ON DELETE CASCADE
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS messages (
      id TEXT PRIMARY KEY,
      from_user TEXT NOT NULL,
      channel TEXT NOT NULL,
      text TEXT,
      ts BIGINT NOT NULL,
      replyTo TEXT,
      file TEXT,
      voice TEXT,
      encrypted BOOLEAN DEFAULT FALSE,
      FOREIGN KEY (from_user) REFERENCES users(username) ON DELETE CASCADE,
      FOREIGN KEY (channel) REFERENCES channels(id) ON DELETE CASCADE
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS webrtc_offers (
      fromUser TEXT NOT NULL,
      toUser TEXT NOT NULL,
      offer TEXT NOT NULL,
      channel TEXT NOT NULL,
      timestamp BIGINT NOT NULL,
      PRIMARY KEY (fromUser, toUser)
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS webrtc_answers (
      fromUser TEXT NOT NULL,
      toUser TEXT NOT NULL,
      answer TEXT NOT NULL,
      timestamp BIGINT NOT NULL,
      PRIMARY KEY (fromUser, toUser)
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS ice_candidates (
      fromUser TEXT NOT NULL,
      toUser TEXT NOT NULL,
      candidate TEXT NOT NULL,
      timestamp BIGINT NOT NULL
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS two_factor_secrets (
      username TEXT PRIMARY KEY,
      secret TEXT NOT NULL,
      FOREIGN KEY (username) REFERENCES users(username) ON DELETE CASCADE
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS voice_messages (
      voiceId TEXT PRIMARY KEY,
      username TEXT NOT NULL,
      channel TEXT NOT NULL,
      duration INTEGER NOT NULL,
      timestamp BIGINT NOT NULL,
      FOREIGN KEY (username) REFERENCES users(username) ON DELETE CASCADE
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS files (
      id TEXT PRIMARY KEY,
      filename TEXT NOT NULL,
      originalName TEXT NOT NULL,
      mimetype TEXT NOT NULL,
      size INTEGER NOT NULL,
      uploadedAt BIGINT NOT NULL,
      uploadedBy TEXT NOT NULL,
      FOREIGN KEY (uploadedBy) REFERENCES users(username) ON DELETE CASCADE
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS email_verifications (
      username TEXT NOT NULL,
      email TEXT NOT NULL,
      code TEXT NOT NULL,
      expires BIGINT NOT NULL,
      PRIMARY KEY (username, email)
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS password_resets (
      username TEXT NOT NULL,
      token TEXT PRIMARY KEY,
      expires BIGINT NOT NULL,
      FOREIGN KEY (username) REFERENCES users(username) ON DELETE CASCADE
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS bans (
      username TEXT PRIMARY KEY,
      reason TEXT NOT NULL,
      moderator TEXT NOT NULL,
      bannedAt BIGINT NOT NULL,
      expires BIGINT NOT NULL,
      active BOOLEAN DEFAULT TRUE,
      FOREIGN KEY (username) REFERENCES users(username) ON DELETE CASCADE
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS push_subscriptions (
      id TEXT PRIMARY KEY,
      userId TEXT NOT NULL,
      endpoint TEXT NOT NULL,
      keys TEXT NOT NULL,
      userAgent TEXT,
      createdAt BIGINT NOT NULL,
      expires BIGINT NOT NULL,
      errorCount INTEGER DEFAULT 0,
      lastError TEXT,
      FOREIGN KEY (userId) REFERENCES users(username) ON DELETE CASCADE
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS notifications (
      id TEXT PRIMARY KEY,
      userId TEXT NOT NULL,
      type TEXT NOT NULL,
      title TEXT NOT NULL,
      body TEXT,
      data TEXT,
      image TEXT,
      icon TEXT,
      badge TEXT,
      tag TEXT,
      timestamp BIGINT NOT NULL,
      read BOOLEAN DEFAULT FALSE,
      expires BIGINT NOT NULL,
      priority TEXT DEFAULT 'normal',
      actions TEXT,
      FOREIGN KEY (userId) REFERENCES users(username) ON DELETE CASCADE
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS channel_subscriptions (
      userId TEXT NOT NULL,
      channelId TEXT NOT NULL,
      types TEXT NOT NULL,
      PRIMARY KEY (userId, channelId),
      FOREIGN KEY (userId) REFERENCES users(username) ON DELETE CASCADE
    )
  `);
};

const createMySQLTables = async () => {
  const tables = [
    `CREATE TABLE IF NOT EXISTS users (
      username VARCHAR(255) PRIMARY KEY,
      passwordHash TEXT NOT NULL,
      salt TEXT NOT NULL,
      avatar TEXT,
      twoFactorEnabled BOOLEAN DEFAULT FALSE,
      email VARCHAR(255),
      emailVerified BOOLEAN DEFAULT FALSE,
      type VARCHAR(50) DEFAULT 'user',
      createdAt DATETIME DEFAULT CURRENT_TIMESTAMP
    ) ENGINE=InnoDB`,

    `CREATE TABLE IF NOT EXISTS tokens (
      token VARCHAR(255) PRIMARY KEY,
      username VARCHAR(255) NOT NULL,
      expires BIGINT NOT NULL,
      FOREIGN KEY (username) REFERENCES users(username) ON DELETE CASCADE
    ) ENGINE=InnoDB`,

    `CREATE TABLE IF NOT EXISTS channels (
      id VARCHAR(255) PRIMARY KEY,
      name VARCHAR(255) UNIQUE NOT NULL,
      creator VARCHAR(255) NOT NULL,
      customId BOOLEAN DEFAULT FALSE,
      createdAt BIGINT NOT NULL,
      FOREIGN KEY (creator) REFERENCES users(username) ON DELETE CASCADE
    ) ENGINE=InnoDB`,

    `CREATE TABLE IF NOT EXISTS channel_members (
      channel VARCHAR(255) NOT NULL,
      username VARCHAR(255) NOT NULL,
      joinedAt BIGINT NOT NULL,
      PRIMARY KEY (channel, username),
      FOREIGN KEY (channel) REFERENCES channels(id) ON DELETE CASCADE,
      FOREIGN KEY (username) REFERENCES users(username) ON DELETE CASCADE
    ) ENGINE=InnoDB`,

    `CREATE TABLE IF NOT EXISTS messages (
      id VARCHAR(255) PRIMARY KEY,
      from_user VARCHAR(255) NOT NULL,
      channel VARCHAR(255) NOT NULL,
      text TEXT,
      ts BIGINT NOT NULL,
      replyTo VARCHAR(255),
      file TEXT,
      voice TEXT,
      encrypted BOOLEAN DEFAULT FALSE,
      FOREIGN KEY (from_user) REFERENCES users(username) ON DELETE CASCADE,
      FOREIGN KEY (channel) REFERENCES channels(id) ON DELETE CASCADE
    ) ENGINE=InnoDB`,

    `CREATE TABLE IF NOT EXISTS webrtc_offers (
      fromUser VARCHAR(255) NOT NULL,
      toUser VARCHAR(255) NOT NULL,
      offer TEXT NOT NULL,
      channel VARCHAR(255) NOT NULL,
      timestamp BIGINT NOT NULL,
      PRIMARY KEY (fromUser, toUser)
    ) ENGINE=InnoDB`,

    `CREATE TABLE IF NOT EXISTS webrtc_answers (
      fromUser VARCHAR(255) NOT NULL,
      toUser VARCHAR(255) NOT NULL,
      answer TEXT NOT NULL,
      timestamp BIGINT NOT NULL,
      PRIMARY KEY (fromUser, toUser)
    ) ENGINE=InnoDB`,

    `CREATE TABLE IF NOT EXISTS ice_candidates (
      fromUser VARCHAR(255) NOT NULL,
      toUser VARCHAR(255) NOT NULL,
      candidate TEXT NOT NULL,
      timestamp BIGINT NOT NULL,
      INDEX idx_from_to (fromUser, toUser)
    ) ENGINE=InnoDB`,

    `CREATE TABLE IF NOT EXISTS two_factor_secrets (
      username VARCHAR(255) PRIMARY KEY,
      secret TEXT NOT NULL,
      FOREIGN KEY (username) REFERENCES users(username) ON DELETE CASCADE
    ) ENGINE=InnoDB`,

    `CREATE TABLE IF NOT EXISTS voice_messages (
      voiceId VARCHAR(255) PRIMARY KEY,
      username VARCHAR(255) NOT NULL,
      channel VARCHAR(255) NOT NULL,
      duration INTEGER NOT NULL,
      timestamp BIGINT NOT NULL,
      FOREIGN KEY (username) REFERENCES users(username) ON DELETE CASCADE
    ) ENGINE=InnoDB`,

    `CREATE TABLE IF NOT EXISTS files (
      id VARCHAR(255) PRIMARY KEY,
      filename VARCHAR(255) NOT NULL,
      originalName VARCHAR(255) NOT NULL,
      mimetype VARCHAR(255) NOT NULL,
      size BIGINT NOT NULL,
      uploadedAt BIGINT NOT NULL,
      uploadedBy VARCHAR(255) NOT NULL,
      FOREIGN KEY (uploadedBy) REFERENCES users(username) ON DELETE CASCADE
    ) ENGINE=InnoDB`,

    `CREATE TABLE IF NOT EXISTS email_verifications (
      username VARCHAR(255) NOT NULL,
      email VARCHAR(255) NOT NULL,
      code VARCHAR(255) NOT NULL,
      expires BIGINT NOT NULL,
      PRIMARY KEY (username, email)
    ) ENGINE=InnoDB`,

    `CREATE TABLE IF NOT EXISTS password_resets (
      username VARCHAR(255) NOT NULL,
      token VARCHAR(255) PRIMARY KEY,
      expires BIGINT NOT NULL,
      FOREIGN KEY (username) REFERENCES users(username) ON DELETE CASCADE
    ) ENGINE=InnoDB`,

    `CREATE TABLE IF NOT EXISTS bans (
      username VARCHAR(255) PRIMARY KEY,
      reason TEXT NOT NULL,
      moderator VARCHAR(255) NOT NULL,
      bannedAt BIGINT NOT NULL,
      expires BIGINT NOT NULL,
      active BOOLEAN DEFAULT TRUE,
      FOREIGN KEY (username) REFERENCES users(username) ON DELETE CASCADE
    ) ENGINE=InnoDB`,

    `CREATE TABLE IF NOT EXISTS push_subscriptions (
      id VARCHAR(255) PRIMARY KEY,
      userId VARCHAR(255) NOT NULL,
      endpoint TEXT NOT NULL,
      keys TEXT NOT NULL,
      userAgent TEXT,
      createdAt BIGINT NOT NULL,
      expires BIGINT NOT NULL,
      errorCount INTEGER DEFAULT 0,
      lastError TEXT,
      FOREIGN KEY (userId) REFERENCES users(username) ON DELETE CASCADE
    ) ENGINE=InnoDB`,

    `CREATE TABLE IF NOT EXISTS notifications (
      id VARCHAR(255) PRIMARY KEY,
      userId VARCHAR(255) NOT NULL,
      type VARCHAR(50) NOT NULL,
      title TEXT NOT NULL,
      body TEXT,
      data TEXT,
      image TEXT,
      icon TEXT,
      badge TEXT,
      tag TEXT,
      timestamp BIGINT NOT NULL,
      read BOOLEAN DEFAULT FALSE,
      expires BIGINT NOT NULL,
      priority VARCHAR(50) DEFAULT 'normal',
      actions TEXT,
      FOREIGN KEY (userId) REFERENCES users(username) ON DELETE CASCADE
    ) ENGINE=InnoDB`,

    `CREATE TABLE IF NOT EXISTS channel_subscriptions (
      userId VARCHAR(255) NOT NULL,
      channelId VARCHAR(255) NOT NULL,
      types TEXT NOT NULL,
      PRIMARY KEY (userId, channelId),
      FOREIGN KEY (userId) REFERENCES users(username) ON DELETE CASCADE
    ) ENGINE=InnoDB`
  ];

  for (const tableSql of tables) {
    try {
      await mysqlPool.execute(tableSql);
    } catch (error) {
      console.error('Error creating table:', error);
    }
  }
};

const executeSQLite = (sql, params = []) => {
  try {
    if (sql.trim().toUpperCase().startsWith('SELECT')) {
      const stmt = db.prepare(sql);
      const results = [];
      while (stmt.step()) {
        results.push(stmt.getAsObject());
      }
      stmt.free();
      return results;
    } else {
      const stmt = db.prepare(sql);
      stmt.bind(params);
      stmt.step();
      stmt.free();
      return { changes: db.getRowsModified() };
    }
  } catch (error) {
    console.error('SQLite error:', error);
    throw error;
  }
};

const executeMySQL = async (sql, params = []) => {
  try {
    const [results] = await mysqlPool.execute(sql, params);
    return results;
  } catch (error) {
    console.error('MySQL error:', error);
    throw error;
  }
};

const executeQuery = async (sql, params = []) => {
  if (dbType === 'mysql') {
    return await executeMySQL(sql, params);
  } else {
    return executeSQLite(sql, params);
  }
};

const pbkdf2 = (password, salt) => {
  return crypto.pbkdf2Sync(
    password,
    salt,
    config.security.pbkdf2.iterations,
    config.security.pbkdf2.keylen,
    config.security.pbkdf2.digest
  ).toString("hex");
};

const sha256 = (str) => {
  return crypto.createHash("sha256").update(str).digest("hex");
};

export async function registerUser(username, passwordPlain) {
  const existing = await executeQuery('SELECT username FROM users WHERE username = ?', [username]);
  if (existing.length > 0) return false;

  const salt = crypto.randomBytes(16).toString("hex");
  const passwordHash = pbkdf2(passwordPlain, salt);
  
  await executeQuery(
    'INSERT INTO users (username, passwordHash, salt) VALUES (?, ?, ?)',
    [username, passwordHash, salt]
  );
  
  return true;
}

export async function authenticate(username, passwordPlain) {
  const users = await executeQuery('SELECT * FROM users WHERE username = ?', [username]);
  if (users.length === 0) return null;

  const u = users[0];
  if (u.salt) {
    const check = pbkdf2(passwordPlain, u.salt);
    return check === u.passwordHash ? u.username : null;
  } else {
    const check = sha256(passwordPlain);
    return check === u.passwordHash ? u.username : null;
  }
}

export async function saveToken(username, token, expires) {
  await executeQuery('DELETE FROM tokens WHERE expires < ?', [Date.now()]);
  await executeQuery(
    'INSERT OR REPLACE INTO tokens (token, username, expires) VALUES (?, ?, ?)',
    [token, username, expires]
  );
}

export async function validateToken(token) {
  await executeQuery('DELETE FROM tokens WHERE expires < ?', [Date.now()]);
  const tokens = await executeQuery('SELECT username FROM tokens WHERE token = ?', [token]);
  return tokens.length > 0 ? tokens[0].username : null;
}

export async function saveMessage(msg) {
  msg.id = crypto.randomBytes(16).toString("hex");
  
  await executeQuery(
    `INSERT INTO messages (id, from_user, channel, text, ts, replyTo, file, voice, encrypted) 
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [
      msg.id,
      msg.from,
      msg.channel,
      msg.text,
      msg.ts,
      msg.replyTo || null,
      msg.file ? JSON.stringify(msg.file) : null,
      msg.voice ? JSON.stringify(msg.voice) : null,
      msg.encrypted || false
    ]
  );
  
  return msg;
}

export async function getMessages(channel, limit, before) {
  let sql = 'SELECT * FROM messages WHERE channel = ?';
  const params = [channel];
  
  if (before) {
    sql += ' AND ts < ?';
    params.push(before);
  }
  
  sql += ' ORDER BY ts DESC LIMIT ?';
  params.push(limit);
  
  const messages = await executeQuery(sql, params);
  
  return messages.reverse().map(msg => ({
    ...msg,
    from: msg.from_user,
    file: msg.file ? JSON.parse(msg.file) : null,
    voice: msg.voice ? JSON.parse(msg.voice) : null
  }));
}

export async function createChannel(channelName, creator, customId = null) {
  const channelId = customId || sha256(channelName + Date.now());
  
  const existing = await executeQuery(
    'SELECT id FROM channels WHERE id = ? OR name = ?',
    [channelId, channelName]
  );
  
  if (existing.length > 0) return false;
  
  await executeQuery(
    'INSERT INTO channels (id, name, creator, createdAt, customId) VALUES (?, ?, ?, ?, ?)',
    [channelId, channelName, creator, Date.now(), !!customId]
  );
  
  await joinChannel(channelId, creator);
  return channelId;
}

export async function getChannels(username) {
  const channels = await executeQuery(
    `SELECT c.* FROM channels c 
     JOIN channel_members cm ON c.id = cm.channel 
     WHERE cm.username = ?`,
    [username]
  );
  
  return channels;
}

export async function updateChannelName(oldName, newName, username) {
  const channel = await executeQuery(
    'SELECT * FROM channels WHERE name = ? AND creator = ?',
    [oldName, username]
  );
  
  if (channel.length === 0) return false;
  
  const existing = await executeQuery('SELECT id FROM channels WHERE name = ?', [newName]);
  if (existing.length > 0) return false;
  
  await executeQuery('UPDATE channels SET name = ? WHERE name = ?', [newName, oldName]);
  await executeQuery('UPDATE messages SET channel = ? WHERE channel = ?', [newName, oldName]);
  
  return true;
}

export async function searchChannels(query) {
  if (query === "" || query === "%") {
    return await executeQuery('SELECT * FROM channels');
  }
  
  return await executeQuery(
    'SELECT * FROM channels WHERE name LIKE ?',
    [`%${query}%`]
  );
}

export async function joinChannel(channel, username) {
  const channelObj = await executeQuery(
    'SELECT * FROM channels WHERE id = ? OR name = ?',
    [channel, channel]
  );
  
  if (channelObj.length === 0) return false;
  
  const channelId = channelObj[0].id;
  
  const existing = await executeQuery(
    'SELECT * FROM channel_members WHERE channel = ? AND username = ?',
    [channelId, username]
  );
  
  if (existing.length > 0) return true;
  
  await executeQuery(
    'INSERT INTO channel_members (channel, username, joinedAt) VALUES (?, ?, ?)',
    [channelId, username, Date.now()]
  );
  
  return true;
}

export async function leaveChannel(channel, username) {
  const channelObj = await executeQuery(
    'SELECT * FROM channels WHERE id = ? OR name = ?',
    [channel, channel]
  );
  
  if (channelObj.length === 0) return false;
  
  const channelId = channelObj[0].id;
  
  const result = await executeQuery(
    'DELETE FROM channel_members WHERE channel = ? AND username = ?',
    [channelId, username]
  );
  
  if (dbType === 'mysql') {
    return result.affectedRows > 0;
  } else {
    return result.changes > 0;
  }
}

export async function getChannelMembers(channel) {
  const channelObj = await executeQuery(
    'SELECT * FROM channels WHERE id = ? OR name = ?',
    [channel, channel]
  );
  
  if (channelObj.length === 0) return [];
  
  const channelId = channelObj[0].id;
  const members = await executeQuery(
    'SELECT username FROM channel_members WHERE channel = ?',
    [channelId]
  );
  
  return members.map(m => m.username);
}

export async function isChannelMember(channel, username) {
  const channelObj = await executeQuery(
    'SELECT * FROM channels WHERE id = ? OR name = ?',
    [channel, channel]
  );
  
  if (channelObj.length === 0) return false;
  
  const channelId = channelObj[0].id;
  const members = await executeQuery(
    'SELECT * FROM channel_members WHERE channel = ? AND username = ?',
    [channelId, username]
  );
  
  return members.length > 0;
}

export async function saveWebRTCOffer(fromUser, toUser, offer, channel) {
  await executeQuery('DELETE FROM webrtc_offers WHERE timestamp < ?', [Date.now() - 300000]);
  
  await executeQuery(
    `INSERT INTO webrtc_offers (fromUser, toUser, offer, channel, timestamp) 
     VALUES (?, ?, ?, ?, ?) 
     ON DUPLICATE KEY UPDATE offer = ?, channel = ?, timestamp = ?`,
    [fromUser, toUser, offer, channel, Date.now(), offer, channel, Date.now()]
  );
}

export async function getWebRTCOffer(fromUser, toUser) {
  await executeQuery('DELETE FROM webrtc_offers WHERE timestamp < ?', [Date.now() - 300000]);
  
  const offers = await executeQuery(
    'SELECT * FROM webrtc_offers WHERE fromUser = ? AND toUser = ?',
    [fromUser, toUser]
  );
  
  return offers.length > 0 ? offers[0] : null;
}

export async function saveWebRTCAnswer(fromUser, toUser, answer) {
  await executeQuery('DELETE FROM webrtc_answers WHERE timestamp < ?', [Date.now() - 300000]);
  
  await executeQuery(
    `INSERT INTO webrtc_answers (fromUser, toUser, answer, timestamp) 
     VALUES (?, ?, ?, ?) 
     ON DUPLICATE KEY UPDATE answer = ?, timestamp = ?`,
    [fromUser, toUser, answer, Date.now(), answer, Date.now()]
  );
}

export async function getWebRTCAnswer(fromUser, toUser) {
  await executeQuery('DELETE FROM webrtc_answers WHERE timestamp < ?', [Date.now() - 300000]);
  
  const answers = await executeQuery(
    'SELECT * FROM webrtc_answers WHERE fromUser = ? AND toUser = ?',
    [fromUser, toUser]
  );
  
  return answers.length > 0 ? answers[0] : null;
}

export async function saveICECandidate(fromUser, toUser, candidate) {
  await executeQuery('DELETE FROM ice_candidates WHERE timestamp < ?', [Date.now() - 300000]);
  
  await executeQuery(
    'INSERT INTO ice_candidates (fromUser, toUser, candidate, timestamp) VALUES (?, ?, ?, ?)',
    [fromUser, toUser, candidate, Date.now()]
  );
}

export async function getICECandidates(fromUser, toUser) {
  await executeQuery('DELETE FROM ice_candidates WHERE timestamp < ?', [Date.now() - 300000]);
  
  const candidates = await executeQuery(
    'SELECT candidate FROM ice_candidates WHERE fromUser = ? AND toUser = ?',
    [fromUser, toUser]
  );
  
  return candidates.map(c => c.candidate);
}

export async function updateUserAvatar(username, avatarFilename) {
  const result = await executeQuery(
    'UPDATE users SET avatar = ? WHERE username = ?',
    [avatarFilename, username]
  );
  
  if (dbType === 'mysql') {
    return result.affectedRows > 0;
  } else {
    return result.changes > 0;
  }
}

export async function getUsers() {
  const users = await executeQuery('SELECT username, avatar FROM users');
  return users;
}

export async function isTwoFactorEnabled(username) {
  const users = await executeQuery(
    'SELECT twoFactorEnabled FROM users WHERE username = ?',
    [username]
  );
  
  return users.length > 0 ? users[0].twoFactorEnabled : false;
}

export async function getTwoFactorSecret(username) {
  const secrets = await executeQuery(
    'SELECT secret FROM two_factor_secrets WHERE username = ?',
    [username]
  );
  
  return secrets.length > 0 ? secrets[0].secret : null;
}

export async function setTwoFactorSecret(username, secret) {
  await executeQuery(
    `INSERT INTO two_factor_secrets (username, secret) VALUES (?, ?) 
     ON DUPLICATE KEY UPDATE secret = ?`,
    [username, secret, secret]
  );
}

export async function enableTwoFactor(username, enabled) {
  const result = await executeQuery(
    'UPDATE users SET twoFactorEnabled = ? WHERE username = ?',
    [enabled, username]
  );
  
  if (dbType === 'mysql') {
    return result.affectedRows > 0;
  } else {
    return result.changes > 0;
  }
}

export async function saveVoiceMessageInfo(voiceId, username, channel, duration) {
  await executeQuery(
    'INSERT INTO voice_messages (voiceId, username, channel, duration, timestamp) VALUES (?, ?, ?, ?, ?)',
    [voiceId, username, channel, duration, Date.now()]
  );
}

export async function getVoiceMessageDuration(voiceId) {
  const voiceMsgs = await executeQuery(
    'SELECT duration FROM voice_messages WHERE voiceId = ?',
    [voiceId]
  );
  
  return voiceMsgs.length > 0 ? voiceMsgs[0].duration : 0;
}

export async function cleanupOldVoiceMessages(maxAgeSeconds = 86400) {
  const cutoff = Date.now() - (maxAgeSeconds * 1000);
  const result = await executeQuery(
    'DELETE FROM voice_messages WHERE timestamp < ?',
    [cutoff]
  );
  
  if (dbType === 'mysql') {
    return result.affectedRows;
  } else {
    return result.changes;
  }
}

export async function saveFileInfo(fileInfo) {
  await executeQuery(
    `INSERT INTO files (id, filename, originalName, mimetype, size, uploadedAt, uploadedBy) 
     VALUES (?, ?, ?, ?, ?, ?, ?)`,
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
  const files = await executeQuery('SELECT * FROM files WHERE id = ?', [fileId]);
  return files.length > 0 ? files[0] : null;
}

export async function getOriginalFileName(filename) {
  const files = await executeQuery('SELECT originalName FROM files WHERE filename = ?', [filename]);
  return files.length > 0 ? files[0].originalName : filename;
}

export async function getMessageById(messageId) {
  const messages = await executeQuery('SELECT * FROM messages WHERE id = ?', [messageId]);
  
  if (messages.length === 0) return null;
  
  const msg = messages[0];
  return {
    ...msg,
    from: msg.from_user,
    file: msg.file ? JSON.parse(msg.file) : null,
    voice: msg.voice ? JSON.parse(msg.voice) : null
  };
}

export async function setUserEmail(username, email) {
  const result = await executeQuery(
    'UPDATE users SET email = ?, emailVerified = TRUE WHERE username = ?',
    [email, username]
  );
  
  if (dbType === 'mysql') {
    return result.affectedRows > 0;
  } else {
    return result.changes > 0;
  }
}

export async function getUserByEmail(email) {
  const users = await executeQuery('SELECT username FROM users WHERE email = ?', [email]);
  return users.length > 0 ? users[0].username : null;
}

export async function createEmailVerification(username, email, code) {
  await executeQuery('DELETE FROM email_verifications WHERE expires < ?', [Date.now()]);
  
  await executeQuery(
    `INSERT INTO email_verifications (username, email, code, expires) 
     VALUES (?, ?, ?, ?) 
     ON DUPLICATE KEY UPDATE code = ?, expires = ?`,
    [username, email, code, Date.now() + 24 * 60 * 60 * 1000, code, Date.now() + 24 * 60 * 60 * 1000]
  );
  
  return true;
}

export async function verifyEmailCode(username, email, code) {
  await executeQuery('DELETE FROM email_verifications WHERE expires < ?', [Date.now()]);
  
  const verifications = await executeQuery(
    'SELECT * FROM email_verifications WHERE username = ? AND email = ? AND code = ?',
    [username, email, code]
  );
  
  if (verifications.length > 0) {
    await executeQuery(
      'DELETE FROM email_verifications WHERE username = ? AND email = ?',
      [username, email]
    );
    return true;
  }
  
  return false;
}

export async function createPasswordReset(username, token) {
  await executeQuery('DELETE FROM password_resets WHERE expires < ?', [Date.now()]);
  
  await executeQuery(
    'INSERT INTO password_resets (username, token, expires) VALUES (?, ?, ?)',
    [username, token, Date.now() + 60 * 60 * 1000]
  );
  
  return true;
}

export async function usePasswordReset(token, newPassword) {
  await executeQuery('DELETE FROM password_resets WHERE expires < ?', [Date.now()]);
  
  const resets = await executeQuery('SELECT * FROM password_resets WHERE token = ?', [token]);
  if (resets.length === 0) return false;

  const reset = resets[0];
  const salt = crypto.randomBytes(16).toString("hex");
  const passwordHash = pbkdf2(newPassword, salt);
  
  await executeQuery(
    'UPDATE users SET passwordHash = ?, salt = ? WHERE username = ?',
    [passwordHash, salt, reset.username]
  );
  
  await executeQuery('DELETE FROM password_resets WHERE token = ?', [token]);
  return true;
}

export async function setUserType(username, type) {
  const result = await executeQuery(
    'UPDATE users SET type = ? WHERE username = ?',
    [type, username]
  );
  
  if (dbType === 'mysql') {
    return result.affectedRows > 0;
  } else {
    return result.changes > 0;
  }
}

export async function saveBan(banInfo) {
  await executeQuery('DELETE FROM bans WHERE expires < ?', [Date.now()]);
  
  await executeQuery(
    `INSERT INTO bans (username, reason, moderator, bannedAt, expires, active) 
     VALUES (?, ?, ?, ?, ?, ?) 
     ON DUPLICATE KEY UPDATE reason = ?, moderator = ?, bannedAt = ?, expires = ?, active = ?`,
    [
      banInfo.username,
      banInfo.reason,
      banInfo.moderator,
      banInfo.bannedAt,
      banInfo.expires,
      banInfo.active,
      banInfo.reason,
      banInfo.moderator,
      banInfo.bannedAt,
      banInfo.expires,
      banInfo.active
    ]
  );
  
  return true;
}

export async function getBan(username) {
  await executeQuery('DELETE FROM bans WHERE expires < ?', [Date.now()]);
  
  const bans = await executeQuery('SELECT * FROM bans WHERE username = ? AND active = TRUE', [username]);
  return bans.length > 0 ? bans[0] : null;
}

export async function removeBan(username) {
  const result = await executeQuery('DELETE FROM bans WHERE username = ?', [username]);
  
  if (dbType === 'mysql') {
    return result.affectedRows > 0;
  } else {
    return result.changes > 0;
  }
}

export async function savePushSubscription(userId, subscription) {
  await executeQuery(
    `INSERT INTO push_subscriptions (id, userId, endpoint, keys, userAgent, createdAt, expires, errorCount, lastError) 
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) 
     ON DUPLICATE KEY UPDATE endpoint = ?, keys = ?, userAgent = ?, createdAt = ?, expires = ?, errorCount = ?, lastError = ?`,
    [
      subscription.id,
      userId,
      subscription.endpoint,
      JSON.stringify(subscription.keys),
      subscription.userAgent || '',
      subscription.createdAt,
      subscription.expires,
      subscription.errorCount || 0,
      subscription.lastError || null,
      subscription.endpoint,
      JSON.stringify(subscription.keys),
      subscription.userAgent || '',
      subscription.createdAt,
      subscription.expires,
      subscription.errorCount || 0,
      subscription.lastError || null
    ]
  );
}

export async function deletePushSubscription(userId, subscriptionId) {
  await executeQuery(
    'DELETE FROM push_subscriptions WHERE userId = ? AND id = ?',
    [userId, subscriptionId]
  );
}

export async function getPushSubscriptions(userId) {
  const subscriptions = await executeQuery(
    'SELECT * FROM push_subscriptions WHERE userId = ?',
    [userId]
  );
  
  return subscriptions.map(sub => ({
    ...sub,
    keys: JSON.parse(sub.keys)
  }));
}

export async function saveNotification(notification) {
  await executeQuery(
    `INSERT INTO notifications (id, userId, type, title, body, data, image, icon, badge, tag, timestamp, read, expires, priority, actions) 
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [
      notification.id,
      notification.userId,
      notification.type,
      notification.title,
      notification.body,
      JSON.stringify(notification.data || {}),
      notification.image,
      notification.icon,
      notification.badge,
      notification.tag,
      notification.timestamp,
      notification.read,
      notification.expires,
      notification.priority,
      JSON.stringify(notification.actions || [])
    ]
  );
}

export async function markNotificationAsRead(userId, notificationId) {
  await executeQuery(
    'UPDATE notifications SET read = TRUE WHERE userId = ? AND id = ?',
    [userId, notificationId]
  );
}

export async function markAllNotificationsAsRead(userId) {
  await executeQuery(
    'UPDATE notifications SET read = TRUE WHERE userId = ?',
    [userId]
  );
}

export async function getUserNotifications(userId, options = {}) {
  const { limit = 50, offset = 0, unreadOnly = false, types = [] } = options;
  
  let sql = 'SELECT * FROM notifications WHERE userId = ?';
  const params = [userId];
  
  if (unreadOnly) {
    sql += ' AND read = FALSE';
  }
  
  if (types.length > 0) {
    const placeholders = types.map(() => '?').join(',');
    sql += ` AND type IN (${placeholders})`;
    params.push(...types);
  }
  
  sql += ' ORDER BY timestamp DESC LIMIT ? OFFSET ?';
  params.push(limit, offset);
  
  const notifications = await executeQuery(sql, params);
  
  return notifications.map(notif => ({
    ...notif,
    data: JSON.parse(notif.data || '{}'),
    actions: JSON.parse(notif.actions || '[]')
  }));
}

export async function getUnreadNotificationCount(userId) {
  const result = await executeQuery(
    'SELECT COUNT(*) as count FROM notifications WHERE userId = ? AND read = FALSE',
    [userId]
  );
  
  return result[0].count;
}

export async function deleteNotification(userId, notificationId) {
  await executeQuery(
    'DELETE FROM notifications WHERE userId = ? AND id = ?',
    [userId, notificationId]
  );
}

export async function cleanupExpiredSubscriptions(userId, currentTime) {
  await executeQuery(
    'DELETE FROM push_subscriptions WHERE userId = ? AND expires < ?',
    [userId, currentTime]
  );
}

export async function cleanupExpiredNotifications() {
  await executeQuery(
    'DELETE FROM notifications WHERE expires < ?',
    [Date.now()]
  );
}

export async function saveChannelSubscription(userId, channelId, types) {
  await executeQuery(
    `INSERT INTO channel_subscriptions (userId, channelId, types) 
     VALUES (?, ?, ?) 
     ON DUPLICATE KEY UPDATE types = ?`,
    [userId, channelId, JSON.stringify(types), JSON.stringify(types)]
  );
}

export async function deleteChannelSubscription(userId, channelId) {
  await executeQuery(
    'DELETE FROM channel_subscriptions WHERE userId = ? AND channelId = ?',
    [userId, channelId]
  );
}

export async function getUserChannelSubscriptions(userId) {
  const subscriptions = await executeQuery(
    'SELECT * FROM channel_subscriptions WHERE userId = ?',
    [userId]
  );
  
  return subscriptions.map(sub => ({
    ...sub,
    types: JSON.parse(sub.types)
  }));
}

export function validateUsername(username) {
  return typeof username === 'string' && 
         username.length >= 3 && 
         username.length <= 20 && 
         /^[a-zA-Z0-9_]+$/.test(username);
}

await initDatabase();
