import { Router } from 'express';
import { validateResult } from '../middlewares/validate.middleware';
import { ShellcodeController } from '../controllers/shellcode.controller';
import { ShellcodeSchema } from '../schemas/shellcode.schema';
import { CompilerController } from '../controllers/compiler.controller';
import { CompileSchema } from '../schemas/compile.schema';
import { PayloadController } from '../controllers/payload.controller';
import { PayloadSchema } from '../schemas/payload.schema';
import { IATController } from '../controllers/iat.controller';

const router = Router();

const shellcodeController = new ShellcodeController();
const compilerController = new CompilerController();
const payloadController = new PayloadController();
const iatController = new IATController();

router.post('/msfvenom-shellcode', validateResult(ShellcodeSchema), shellcodeController.generate);
router.post('/compile', validateResult(CompileSchema), compilerController.compile);
router.post('/generate-payload', validateResult(PayloadSchema), payloadController.generate);
router.get('/iat-functions', iatController.listFunctions);

export default router;
