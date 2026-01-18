import { z } from 'zod';

export const CompileSchema = z.object({
    code: z.string().min(1, "Source code is required"),
    output: z.enum(['exe', 'dll']),
    flags: z.array(z.string()).optional().default([])
});

export type CompileRequest = z.infer<typeof CompileSchema>;
