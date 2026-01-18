"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.ShellcodeController = void 0;
const docker_service_1 = require("../services/docker.service");
class ShellcodeController {
    constructor() {
        this.generate = (req, res) => __awaiter(this, void 0, void 0, function* () {
            try {
                const options = req.body;
                console.log(`[Controller] Generating shellcode: ${options.payload} LHOST=${options.lhost}`);
                const shellcode = yield this.dockerService.generateShellcode(options);
                res.json({
                    status: 'success',
                    encoding: 'base64',
                    format: options.format || 'raw',
                    shellcode: shellcode.toString('base64')
                });
            }
            catch (error) {
                console.error('[Controller] Error:', error.message);
                res.status(500).json({ error: 'Generation failed', details: error.message });
            }
        });
        this.dockerService = new docker_service_1.DockerService();
    }
}
exports.ShellcodeController = ShellcodeController;
