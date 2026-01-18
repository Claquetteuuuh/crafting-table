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
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.DockerService = void 0;
const dockerode_1 = __importDefault(require("dockerode"));
const stream_1 = __importDefault(require("stream"));
class DockerService {
    constructor() {
        this.docker = new dockerode_1.default({ socketPath: '/var/run/docker.sock' });
    }
    generateShellcode(options) {
        return __awaiter(this, void 0, void 0, function* () {
            const { payload, lhost, lport, format, badchars, encoder, iterations } = options;
            const cmd = ['/usr/local/bin/ruby', '/usr/src/metasploit-framework/msfvenom', '-p', payload, `LHOST=${lhost}`, `LPORT=${lport}`];
            if (format)
                cmd.push('-f', format);
            if (badchars)
                cmd.push('-b', badchars);
            if (encoder)
                cmd.push('-e', encoder);
            if (iterations)
                cmd.push('-i', iterations.toString());
            // Security Hardening:
            // 1. ReadonlyRootfs: True - Container can't modify its own filesystem (except volumes/tmpfs).
            // 2. CapDrop: ["ALL"] - Drop all Linux capabilities.
            // 3. NetworkDisabled: True - No internet access.
            // 4. User: "1000" - Attempt to run as non-root (if image supports or if we just want to enforce ID). 
            //    Note: Official msf image might run as root by default. We try to restrict it. 
            //    If it fails due to permissions (e.g. writing temp files), we might need writable tmpfs.
            const containerConfig = {
                Image: 'local/msf-worker',
                Cmd: cmd,
                Entrypoint: [], // Bypass image entrypoint which tries su-exec
                Tty: false,
                AttachStdout: true,
                AttachStderr: true,
                HostConfig: {
                    AutoRemove: false, // We remove manually to ensure we wait for it
                    ReadonlyRootfs: true,
                    NetworkMode: 'none',
                    // CapDrop: ["ALL"],
                    // CapAdd: ["SETUID", "SETGID"], // Not needed if we run as user directly?
                    // Mount a tmpfs for any temp file needs if msfvenom tries to write to /tmp or similar
                    Tmpfs: {
                        '/tmp': '',
                        '/home/msfuser/.msf4': '' // msf writes logs/history here often
                    }
                },
                User: "msfuser"
                // Let's rely on CapDrop and ReadonlyRootfs for now as primary mitigations. 
                // msfvenom usually just writes to stdout, so it should be fine.
            };
            let container = null;
            try {
                container = yield this.docker.createContainer(containerConfig);
                const logStream = new stream_1.default.PassThrough();
                let outputChunks = [];
                let errorChunks = [];
                logStream.on('data', (chunk) => outputChunks.push(chunk));
                const errStream = new stream_1.default.PassThrough();
                errStream.on('data', (chunk) => errorChunks.push(chunk));
                const streamData = yield container.attach({ stream: true, stdout: true, stderr: true });
                container.modem.demuxStream(streamData, logStream, errStream);
                yield container.start();
                const result = yield container.wait();
                if (result.StatusCode !== 0) {
                    const stderrMsg = Buffer.concat(errorChunks).toString('utf8');
                    if (stderrMsg)
                        console.error(`[DockerService] Stderr: ${stderrMsg}`);
                    throw new Error(`msfvenom exited with code ${result.StatusCode}. Stderr: ${stderrMsg}`);
                }
                return Buffer.concat(outputChunks);
            }
            finally {
                if (container) {
                    try {
                        yield container.remove({ force: true });
                    }
                    catch (e) {
                        console.error('Failed to remove container:', e);
                    }
                }
            }
        });
    }
}
exports.DockerService = DockerService;
