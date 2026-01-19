import { z } from 'zod';

export const ShellcodeSchema = z.object({
    payload: z.string().regex(/^[a-zA-Z0-9\/_]+$/, "Invalid payload format"),
    lhost: z.string().ip({ version: "v4" }).or(z.string().min(1, "LHOST cannot be empty")), // Basic string check if it's a domain, or proper IP
    lport: z.string().regex(/^\d+$/, "LPORT must be distinct numbers").or(z.number()),
    format: z.string().regex(/^[a-zA-Z0-9]*$/, "Invalid format").optional(),
    badchars: z.string().refine(val => val === "" || /^(\\x[0-9a-fA-F]{2})+$/.test(val), {
        message: "Badchars must be in \\xHH format"
    }).optional(),
    encoder: z.string().regex(/^[a-zA-Z0-9\/_]*$/).optional(),
    iterations: z.number().int().min(1).optional(),
});

export type ShellcodeRequest = z.infer<typeof ShellcodeSchema>;
