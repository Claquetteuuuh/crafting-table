import { Router } from 'express';
import { ShellcodeController } from '../controllers/shellcode.controller';
import { CompilerController } from '../controllers/compiler.controller';
import { validateResult } from '../middlewares/validate.middleware';
import { ShellcodeSchema } from '../schemas/shellcode.schema';
import { CompileSchema } from '../schemas/compile.schema';

const router = Router();
const shellcodeController = new ShellcodeController();
const compilerController = new CompilerController();

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

export default router;
