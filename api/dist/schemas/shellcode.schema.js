"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.ShellcodeSchema = void 0;
const zod_1 = require("zod");
exports.ShellcodeSchema = zod_1.z.object({
    payload: zod_1.z.string().regex(/^[a-zA-Z0-9\/_]+$/, "Invalid payload format"),
    lhost: zod_1.z.string().ip({ version: "v4" }).or(zod_1.z.string().min(1, "LHOST cannot be empty")), // Basic string check if it's a domain, or proper IP
    lport: zod_1.z.string().regex(/^\d+$/, "LPORT must be distinct numbers").or(zod_1.z.number()),
    format: zod_1.z.string().regex(/^[a-zA-Z0-9]+$/, "Invalid format").optional(),
    badchars: zod_1.z.string().regex(/^(\\x[0-9a-fA-F]{2})+$/, "Badchars must be in \\xHH format").optional(),
    encoder: zod_1.z.string().regex(/^[a-zA-Z0-9\/_]+$/).optional(),
    iterations: zod_1.z.number().int().min(1).optional(),
});
