import { Request, Response } from 'express';
import { DockerService } from '../services/docker.service';
import { ShellcodeRequest } from '../schemas/shellcode.schema';

export class ShellcodeController {
    private dockerService: DockerService;

    constructor() {
        this.dockerService = new DockerService();
    }

    generate = async (req: Request, res: Response) => {
        try {
            const options: ShellcodeRequest = req.body;
            console.log(`[Controller] Generating shellcode: ${options.payload} LHOST=${options.lhost}`);

            const shellcode = await this.dockerService.generateShellcode(options);

            res.json({
                status: 'success',
                encoding: 'base64',
                format: options.format || 'raw',
                shellcode: shellcode.toString('base64')
            });

        } catch (error: any) {
            console.error('[Controller] Error:', error.message);
            res.status(500).json({ error: 'Generation failed', details: error.message });
        }
    }
}
