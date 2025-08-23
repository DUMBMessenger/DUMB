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
