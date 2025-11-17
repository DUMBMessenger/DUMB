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

export const validateUsername = (username) => {
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
  if (!key || !encryptedData.encrypted) return encryptedData.content || encryptedData;
  
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
    if (msg.encrypted && config.security.encryptionKey && typeof msg.text === 'object') {
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
export const getMessageById = backend.getMessageById;
export const setUserEmail = backend.setUserEmail;
export const getUserByEmail = backend.getUserByEmail;
export const createEmailVerification = backend.createEmailVerification;
export const verifyEmailCode = backend.verifyEmailCode;
export const createPasswordReset = backend.createPasswordReset;
export const usePasswordReset = backend.usePasswordReset;
export const setUserType = backend.setUserType;
export const saveBan = backend.saveBan;
export const getBan = backend.getBan;
export const removeBan = backend.removeBan;
export const savePushSubscription = async (userId, subscription) => {
  return await backend.savePushSubscription(userId, subscription);
};
export const deletePushSubscription = async (userId, subscriptionId) => {
  return await backend.deletePushSubscription(userId, subscriptionId);
};
export const getPushSubscriptions = async (userId) => {
  return await backend.getPushSubscriptions(userId);
};
export const saveNotification = async (notification) => {
  return await backend.saveNotification(notification);
};
export const markNotificationAsRead = async (userId, notificationId) => {
  return await backend.markNotificationAsRead(userId, notificationId);
};
export const markAllNotificationsAsRead = async (userId) => {
  return await backend.markAllNotificationsAsRead(userId);
};
export const getUserNotifications = async (userId, options = {}) => {
  return await backend.getUserNotifications(userId, options);
};
export const getUnreadNotificationCount = async (userId) => {
  return await backend.getUnreadNotificationCount(userId);
};
export const deleteNotification = async (userId, notificationId) => {
  return await backend.deleteNotification(userId, notificationId);
};
export const cleanupExpiredSubscriptions = async (userId, currentTime) => {
  return await backend.cleanupExpiredSubscriptions(userId, currentTime);
};
export const cleanupExpiredNotifications = async () => {
  return await backend.cleanupExpiredNotifications();
};
export const saveChannelSubscription = async (userId, channelId, types) => {
  return await backend.saveChannelSubscription(userId, channelId, types);
};
export const deleteChannelSubscription = async (userId, channelId) => {
  return await backend.deleteChannelSubscription(userId, channelId);
};
export const getUserChannelSubscriptions = async (userId) => {
  return await backend.getUserChannelSubscriptions(userId);
};
