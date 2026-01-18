"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.CompileSchema = void 0;
const zod_1 = require("zod");
exports.CompileSchema = zod_1.z.object({
    code: zod_1.z.string().min(1, "Source code is required"),
    output: zod_1.z.enum(['exe', 'dll']),
    flags: zod_1.z.array(zod_1.z.string()).optional().default([])
});
