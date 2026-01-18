import { Request, Response } from 'express';
import { CompilerService } from '../services/compiler.service';
import { CompileRequest } from '../schemas/compile.schema';

export class CompilerController {
    private compilerService: CompilerService;

    constructor() {
        this.compilerService = new CompilerService();
    }

    compile = async (req: Request, res: Response) => {
        try {
            const options: CompileRequest = req.body;
            console.log(`[Compiler] Compiling ${options.output} with flags: ${options.flags}`);

            const binaryBase64 = await this.compilerService.compile(options);

            res.json({
                status: 'success',
                format: options.output,
                binary: binaryBase64.trim() // Trim newlines from base64 output
            });

        } catch (error: any) {
            console.error('[Compiler] Error:', error.message);
            res.status(500).json({ error: 'Compilation failed', details: error.message });
        }
    }
}
