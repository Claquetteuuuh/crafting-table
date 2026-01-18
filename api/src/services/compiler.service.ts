import Docker from 'dockerode';
import stream from 'stream';
import { CompileRequest } from '../schemas/compile.schema';

export class CompilerService {
    private docker: Docker;

    constructor() {
        this.docker = new Docker({ socketPath: '/var/run/docker.sock' });
    }

    async compile(options: CompileRequest): Promise<string> {
        const { code, output, flags } = options;
        const isWin = true; // For now assuming we always target windows per user request

        // Command construction
        // nim c -d:mingw --app:gui|console --out:out.exe source.nim
        let cmd = ['nim', 'c', '-d:mingw'];

        // Default to release mode for smaller binaries, unless flags override
        cmd.push('-d:release');
        cmd.push('--opt:size');

        if (output === 'dll') {
            cmd.push('--app:lib');
            cmd.push('--nomain');
        }

        // Add user flags
        if (flags) {
            cmd = cmd.concat(flags);
        }

        const outputFile = output === 'dll' ? '/workspace/payload.dll' : '/workspace/payload.exe';
        cmd.push(`--out:${outputFile}`);
        cmd.push('/workspace/source.nim');

        const containerConfig = {
            Image: 'local/nim-worker',
            // We start with a shell to orchestrate: echo code > source.nim && compile && base64 output
            // Note: Passing large code via echo arg list is risky. 
            // Better: Create container with OpenStdin, stream code to `cat > source.nim`, then exec compile.
            // Redirect nim output to stderr (> &2) so stdout only contains the base64 output
            Cmd: ['/bin/sh', '-c', 'cat > /workspace/source.nim && (' + cmd.join(' ') + ' >&2) && base64 ' + outputFile],
            Tty: false,
            OpenStdin: true,
            StdinOnce: true,
            AttachStdout: true,
            AttachStderr: true,
            HostConfig: {
                AutoRemove: false, // We remove manually to ensure we wait for it
                NetworkMode: 'none',
                CapDrop: ['ALL'],
                ReadonlyRootfs: true,
                // We need writable workspace.
                Tmpfs: {
                    '/workspace': ''
                }
            },
            User: 'nimuser'
        };

        let container: Docker.Container | null = null;

        try {
            container = await this.docker.createContainer(containerConfig);

            const logStream = new stream.PassThrough();
            const outputChunks: Buffer[] = [];
            const errorChunks: Buffer[] = [];

            logStream.on('data', (chunk) => outputChunks.push(chunk));

            const errStream = new stream.PassThrough();
            errStream.on('data', (chunk) => errorChunks.push(chunk));

            const streamData = await container.attach({ stream: true, hijack: true, stdin: true, stdout: true, stderr: true });
            container.modem.demuxStream(streamData, logStream, errStream);

            await container.start();

            // Write code to stdin
            streamData.write(code);
            streamData.end();

            const result = await container.wait();

            if (result.StatusCode !== 0) {
                const stderrMsg = Buffer.concat(errorChunks).toString('utf8');
                // If compilation fails, stdout might contain compiler errors too (Nim writes some to stdout?)
                throw new Error(`Compilation failed with code ${result.StatusCode}. Stderr: ${stderrMsg}`);
            }

            // Return the captured stdout which contains the base64 string
            return Buffer.concat(outputChunks).toString('utf8');

        } catch (e) {
            throw e;
        } finally {
            if (container) await container.remove({ force: true }).catch(() => { { } });
        }
    }
}
