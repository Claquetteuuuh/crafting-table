import { z } from 'zod';

export const CompileSchema = z.object({
    code: z.string().min(1, "Source code is required"),
    output: z.enum(['exe', 'dll']),
    arch: z.enum(['amd64', 'i386', 'arm64']).optional().default('amd64'),
    flags: z.array(z.string()).optional().default([]),
    gui_mode: z.boolean().optional().default(false)
});

export type CompileRequest = z.infer<typeof CompileSchema>;
