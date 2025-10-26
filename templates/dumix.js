// todo: do a doc in wiki

import path from "path";
import * as url from "url";
import fs from "fs";
import EventEmitter from "events";

const hooks = [];
const moduleHooks = [];
const pluginState = new Map();
const events = new EventEmitter();

export function hook(modulePath, targetPath, handler, options = {}) {
    hooks.push({ modulePath, targetPath, handler, ...options });
}

export function hookModule(moduleName, targetPath, handler, options = {}) {
    moduleHooks.push({ moduleName, targetPath, handler, ...options });
}

export async function loadPlugins(folder = "./plugins") {
    const files = fs.readdirSync(folder).filter(f => f.endsWith(".js"));
    for (const file of files) {
        await import(path.resolve(folder, file));
    }
}

export function on(event, listener) {
    events.on(event, listener);
}

export function emit(event, ...args) {
    events.emit(event, ...args);
}

export function getPluginState(pluginName) {
    if (!pluginState.has(pluginName)) pluginState.set(pluginName, {});
    return pluginState.get(pluginName);
}

export async function applyPlugins() {
    const allHooks = [...hooks, ...moduleHooks].sort((a, b) => (b.priority || 0) - (a.priority || 0));

    for (const hookItem of allHooks) {
        let mod;
        if (hookItem.modulePath) {
            mod = await import(url.pathToFileURL(path.resolve(hookItem.modulePath)));
        } else if (hookItem.moduleName) {
            mod = await import(hookItem.moduleName);
        }

        patchTarget(mod, hookItem.targetPath, hookItem.handler, hookItem);
    }
}

function patchTarget(mod, targetPath, handler, options) {
    const parts = targetPath.split(".");
    let target = mod;
    for (let i = 0; i < parts.length - 1; i++) {
        if (!(parts[i] in target)) {
            console.warn(`[dumix] path ${targetPath} not found`);
            return;
        }
        target = target[parts[i]];
    }

    const methodName = parts[parts.length - 1];
    const original = target[methodName];

    if (typeof original !== "function") {
        console.warn(`[dumix] method ${targetPath} is not a function`);
        return;
    }

    let patched;

    if (typeof handler === "function") {
        patched = handler(original);
    } else {
        const { before, after, replace } = handler;
        if (typeof replace === "function") {
            patched = replace(original);
        } else {
            patched = async function (...args) {
                if (typeof before === "function") await before.apply(this, args);
                const result = await original.apply(this, args);
                if (typeof after === "function") await after.apply(this, [result, ...args]);
                return result;
            };
        }
    }

    target[methodName] = patched;
    console.log(`[dumix] mixed ${targetPath} (plugin: ${options.name || "anonymous"})`);
}

export function unhook(targetPath) {
    console.log(`[dumix] unhooking ${targetPath}`);
    // todo: please do unhooking
}
