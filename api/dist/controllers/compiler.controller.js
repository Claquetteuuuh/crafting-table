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
exports.CompilerController = void 0;
const compiler_service_1 = require("../services/compiler.service");
class CompilerController {
    constructor() {
        this.compile = (req, res) => __awaiter(this, void 0, void 0, function* () {
            try {
                const options = req.body;
                console.log(`[Compiler] Compiling ${options.output} with flags: ${options.flags}`);
                const binaryBase64 = yield this.compilerService.compile(options);
                res.json({
                    status: 'success',
                    format: options.output,
                    binary: binaryBase64.trim() // Trim newlines from base64 output
                });
            }
            catch (error) {
                console.error('[Compiler] Error:', error.message);
                res.status(500).json({ error: 'Compilation failed', details: error.message });
            }
        });
        this.compilerService = new compiler_service_1.CompilerService();
    }
}
exports.CompilerController = CompilerController;
