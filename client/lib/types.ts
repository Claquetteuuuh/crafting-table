// API Types matching backend schemas
export interface ShellcodeRequest {
    payload: string;
    lhost: string;
    lport: string | number;
    format?: string;
    badchars?: string;
    encoder?: string;
    iterations?: number;
}

export interface ShellcodeResponse {
    status: string;
    encoding: string;
    format: string;
    shellcode: string;
}

export interface PayloadRequest {
    name: string;
    output: 'exe' | 'dll';
    shellcode?: string;
    shellcode_url?: string;
    xor_key?: string;
    injection_method: 'fiber' | 'thread' | 'early_bird';
    syscall_evasion: 'hells_gate' | 'none';
    anti_sandbox: Array<'cpu_ram' | 'timing' | 'human_behavior'>;
    anti_debug: Array<'is_debugger_present' | 'nt_global_flag'>;
    iat_spoofing: Array<{ dll: string; function_name: string }>;
    export_function_name?: string;
}

export interface PayloadResponse {
    status: string;
    message: string;
    config_summary: {
        name: string;
        output: string;
    };
    source_code: string;
}

export interface CompileRequest {
    code: string;
    output: 'exe' | 'dll';
    arch?: 'amd64' | 'i386' | 'arm64';
    flags?: string[];
}

export interface CompileResponse {
    status: string;
    format: string;
    binary: string;
}

export interface IATFunction {
    dll: string;
    function_name: string;
    description: string;
}

export interface IATFunctionsResponse {
    status: string;
    count: number;
    functions: IATFunction[];
}
