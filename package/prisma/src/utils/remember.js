"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.remember = remember;
function remember(name, getValue) {
    var thusly = globalThis;
    if (!thusly.__prisma_remember) {
        thusly.__prisma_remember = new Map();
    }
    if (!thusly.__prisma_remember.has(name)) {
        thusly.__prisma_remember.set(name, getValue());
    }
    return thusly.__prisma_remember.get(name);
}
