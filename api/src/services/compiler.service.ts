import Docker from 'dockerode';
import stream from 'stream';
import { CompileRequest } from '../schemas/compile.schema';

export class CompilerService {
    private docker: Docker;

    constructor() {
        this.docker = new Docker(); // Auto-detects socket (Windows pipe or Unix socket)
    }

    async compile(options: CompileRequest): Promise<string> {
        const { code, output, flags, arch } = options;
        const isWin = true; // For now assuming we always target windows per user request

        // Command construction
        // nim c -d:mingw --cpu:<arch> --app:gui|console --out:out.exe source.nim
        let cmd = ['nim', 'c', '-d:mingw', `--cpu:${arch}`];

        // Default to release mode for smaller binaries, unless flags override
        // We check if users already specified -d:release
        const userHasRelease = flags?.some(f => f.includes('-d:release'));
        if (!userHasRelease) {
            cmd.push('-d:release');
        }

        if (output === 'dll') {
            cmd.push('--app:lib');
            cmd.push('--nomain');
            cmd.push('--passL:-static');
        }

        // Add user flags
        if (flags) {
            cmd = cmd.concat(flags);
        }

        if (options.gui_mode) {
            cmd.push('--app:gui');
        }

        const outputFile = output === 'dll' ? '/tmp/payload.dll' : '/tmp/payload.exe';
        cmd.push(`--out:${outputFile}`);
        cmd.push(`--nimcache:/tmp/nimcache`);
        cmd.push('/tmp/source.nim');

        console.log(`[Compiler] Executing: ${cmd.join(' ')}`);

        const base64Code = Buffer.from(code).toString('base64');
        let containerConfig: Docker.ContainerCreateOptions;

        if (options.use_llvm) {
            const passName = options.llvm_pass || 'shuffle-strings';
            // For LLVM, we use the nim-llvm-builder image
            // We override the entrypoint to allow us to write the source file first
            containerConfig = {
                Image: 'local/nim-llvm-builder',
                Entrypoint: ['/bin/sh', '-c'],
                Cmd: [
                    `echo "${base64Code}" | base64 -d > /app/source.nim && ` +
                    `build_exe /app/source.nim "${passName}" >&2 && ` +
                    `base64 -w 0 /app/output_final.exe`
                ],
                Tty: false,
                AttachStdout: true,
                AttachStderr: true,
                HostConfig: {
                    AutoRemove: false,
                    NetworkMode: 'none',
                    CapDrop: ['ALL'],
                    ReadonlyRootfs: false, // build_exe needs to write to /app/ir_output and /tmp
                    Tmpfs: {
                        '/tmp': ''
                    }
                },
                User: 'root' // build_exe might need root for some operations or just default to root in that image
            };
        } else {
            // Standard compilation
            containerConfig = {
                Image: 'local/nim-worker',
                // Use base64 to avoid shell escaping issues and corruption
                Cmd: ['/bin/sh', '-c', `echo "${base64Code}" | base64 -d > /tmp/source.nim && (` + cmd.join(' ') + ' >&2) && base64 -w 0 ' + outputFile],
                Tty: false,
                AttachStdout: true,
                AttachStderr: true,
                HostConfig: {
                    AutoRemove: false,
                    NetworkMode: 'none',
                    CapDrop: ['ALL'],
                    ReadonlyRootfs: true,
                    Tmpfs: {
                        '/tmp': ''
                    }
                },
                User: 'nimuser'
            };
        }

        let container: Docker.Container | null = null;

        try {
            container = await this.docker.createContainer(containerConfig);

            const logStream = new stream.PassThrough();
            const outputChunks: Buffer[] = [];
            const errorChunks: Buffer[] = [];

            logStream.on('data', (chunk) => outputChunks.push(chunk));

            const errStream = new stream.PassThrough();
            errStream.on('data', (chunk) => errorChunks.push(chunk));

            const streamData = await container.attach({ stream: true, stdout: true, stderr: true });
            container.modem.demuxStream(streamData, logStream, errStream);

            await container.start();
            const result = await container.wait();

            if (result.StatusCode !== 0) {
                const stderrMsg = Buffer.concat(errorChunks).toString('utf8');
                throw new Error(`Compilation failed with code ${result.StatusCode}. Stderr: ${stderrMsg}`);
            }

            return Buffer.concat(outputChunks).toString('utf8');

        } catch (e) {
            throw e;
        } finally {
            if (container) await container.remove({ force: true }).catch(() => { { } });
        }
    }
}
