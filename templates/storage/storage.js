import config from "../config.js";
import * as jsonBackend from "./slaves/json.js";
import * as sqlsBackend from "./slaves/sqls.js";

let backend;

if (config.storage.type === "json") {
  backend = jsonBackend;
} else if (config.storage.type === "sqlite" || config.storage.type === "mysql") {
  backend = sqlsBackend;
} else {
  throw new Error("Unsupported storage type: " + config.storage.type);
}

export const registerUser = backend.registerUser;
export const authenticate = backend.authenticate;
export const saveToken = backend.saveToken;
export const validateToken = backend.validateToken;
export const saveMessage = backend.saveMessage;
export const getMessages = backend.getMessages;
export const createChannel = backend.createChannel;
export const getChannels = backend.getChannels;
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
