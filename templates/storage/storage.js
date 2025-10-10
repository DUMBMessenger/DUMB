//where you head at?
import config from "../config.js";
import * as jsonBackend from "./slaves/json.js";
import * as sqlsBackend from "./slaves/sqls.js";
import crypto from "crypto";

let backend;

if (config.storage.type === "json") {
  backend = jsonBackend;
} else if (config.storage.type === "sqlite" || config.storage.type === "mysql") {
  backend = sqlsBackend;
} else {
  throw new Error("Unsupported storage type: " + config.storage.type);
}

const usernameRegex = /^[a-zA-Z0-9_-]{3,20}$/;

const validateUsername = (username) => {
  return usernameRegex.test(username);
};

const encryptMessage = (text, key) => {
  if (!key) return text;
  
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipher('aes-256-cbc', key);
  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return {
    iv: iv.toString('hex'),
    content: encrypted,
    encrypted: true
  };
};

const decryptMessage = (encryptedData, key) => {
  if (!key || !encryptedData.encrypted) return encryptedData;
  
  try {
    const iv = Buffer.from(encryptedData.iv, 'hex');
    const decipher = crypto.createDecipher('aes-256-cbc', key);
    let decrypted = decipher.update(encryptedData.content, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
  } catch (error) {
    throw new Error('Decryption failed');
  }
};

export const registerUser = (username, password) => {
  if (!validateUsername(username)) {
    throw new Error("Invalid username format");
  }
  return backend.registerUser(username, password);
};

export const authenticate = backend.authenticate;
export const saveToken = backend.saveToken;
export const validateToken = backend.validateToken;

export const saveMessage = (message) => {
  if (message.encrypted && config.security.encryptionKey && typeof message.text === 'string') {
    message.text = encryptMessage(message.text, config.security.encryptionKey);
  }
  return backend.saveMessage(message);
};

export const getMessages = async (channel, limit, before) => {
  const messages = await backend.getMessages(channel, limit, before);
  
  return messages.map(msg => {
    if (msg.encrypted && config.security.encryptionKey) {
      try {
        msg.text = decryptMessage(msg.text, config.security.encryptionKey);
        msg.encrypted = false;
      } catch (error) {
        msg.text = "[encrypted message - decryption failed]";
      }
    }
    return msg;
  });
};

export const createChannel = backend.createChannel;
export const getChannels = backend.getChannels;
export const updateChannelName = backend.updateChannelName;
export const searchChannels = backend.searchChannels;
export const joinChannel = backend.joinChannel;
export const leaveChannel = backend.leaveChannel;
export const getChannelMembers = backend.getChannelMembers;
export const isChannelMember = backend.isChannelMember;
export const saveWebRTCOffer = backend.saveWebRTCOffer;
export const getWebRTCOffer = backend.getWebRTCOffer;
export const saveWebRTCAnswer = backend.saveWebRTCAnswer;
export const getWebRTCAnswer = backend.getWebRTCAnswer;
export const saveICECandidate = backend.saveICECandidate;
export const getICECandidates = backend.getICECandidates;
export const updateUserAvatar = backend.updateUserAvatar;
export const getUsers = backend.getUsers;
export const isTwoFactorEnabled = backend.isTwoFactorEnabled;
export const getTwoFactorSecret = backend.getTwoFactorSecret;
export const setTwoFactorSecret = backend.setTwoFactorSecret;
export const enableTwoFactor = backend.enableTwoFactor;
export const saveVoiceMessageInfo = backend.saveVoiceMessageInfo;
export const getVoiceMessageDuration = backend.getVoiceMessageDuration;
export const cleanupOldVoiceMessages = backend.cleanupOldVoiceMessages;
export const saveFileInfo = backend.saveFileInfo;
export const getFileInfo = backend.getFileInfo;
export const getOriginalFileName = backend.getOriginalFileName;
export const validateUsername = validateUsername;
