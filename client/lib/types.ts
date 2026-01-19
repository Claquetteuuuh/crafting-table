import { ShellcodeRequest } from './schemas/shellcode.schema';
import { PayloadRequest } from './schemas/payload.schema';
import { CompileRequest } from './schemas/compile.schema';

export type { ShellcodeRequest, PayloadRequest, CompileRequest };

export interface ShellcodeResponse {
    status: string;
    encoding: string;
    format: string;
    shellcode: string;
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
