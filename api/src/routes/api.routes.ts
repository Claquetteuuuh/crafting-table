import { Router } from 'express';
import { ShellcodeController } from '../controllers/shellcode.controller';
import { CompilerController } from '../controllers/compiler.controller';
import { validateResult } from '../middlewares/validate.middleware';
import { ShellcodeSchema } from '../schemas/shellcode.schema';
import { CompileSchema } from '../schemas/compile.schema';
import { PayloadController } from '../controllers/payload.controller';
import { PayloadSchema } from '../schemas/payload.schema';

const router = Router();
const shellcodeController = new ShellcodeController();
const compilerController = new CompilerController();
const payloadController = new PayloadController();

router.post(
    '/msfvenom-shellcode',
    validateResult(ShellcodeSchema),
    shellcodeController.generate
);

router.post(
    '/compile',
    validateResult(CompileSchema),
    compilerController.compile
);

router.post(
    '/generate-payload',
    validateResult(PayloadSchema),
    payloadController.generate
);

export default router;
