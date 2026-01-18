import { Request, Response } from 'express';
import { PayloadRequest } from '../schemas/payload.schema';
import { PayloadService } from '../services/payload.service';

export class PayloadController {
    private payloadService: PayloadService;

    constructor() {
        this.payloadService = new PayloadService();
    }

    generate = async (req: Request, res: Response) => {
        try {
            // Validation is already handled by middleware
            const options: PayloadRequest = req.body;

            console.log(`[Payload] Received request for malware: ${options.name}`);

            const sourceCode = this.payloadService.generateSource(options);

            res.json({
                status: 'success',
                message: 'Payload source generated successfully',
                config_summary: {
                    name: options.name,
                    output: options.output,
                },
                source_code: sourceCode // Returning source for verification
            });

        } catch (error: any) {
            console.error('[Payload] Error:', error.message);
            res.status(500).json({ error: 'Payload generation failed', details: error.message });
        }
    }
}
