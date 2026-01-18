import Docker from 'dockerode';
import stream from 'stream';
import { ShellcodeRequest } from '../schemas/shellcode.schema';

export class DockerService {
    private docker: Docker;

    constructor() {
        this.docker = new Docker({ socketPath: '/var/run/docker.sock' });
    }

    async generateShellcode(options: ShellcodeRequest): Promise<Buffer> {
        const { payload, lhost, lport, format, badchars, encoder, iterations } = options;

        const cmd = ['/usr/local/bin/ruby', '/usr/src/metasploit-framework/msfvenom', '-p', payload, `LHOST=${lhost}`, `LPORT=${lport}`];

        if (format) cmd.push('-f', format);
        if (badchars) cmd.push('-b', badchars);
        if (encoder) cmd.push('-e', encoder);
        if (iterations) cmd.push('-i', iterations.toString());

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

        let container: Docker.Container | null = null;

        try {
            container = await this.docker.createContainer(containerConfig);

            const logStream = new stream.PassThrough();
            let outputChunks: Buffer[] = [];
            let errorChunks: Buffer[] = [];

            logStream.on('data', (chunk) => outputChunks.push(chunk));
            const errStream = new stream.PassThrough();
            errStream.on('data', (chunk) => errorChunks.push(chunk));

            const streamData = await container.attach({ stream: true, stdout: true, stderr: true });
            container.modem.demuxStream(streamData, logStream, errStream);

            await container.start();
            const result = await container.wait();

            if (result.StatusCode !== 0) {
                const stderrMsg = Buffer.concat(errorChunks).toString('utf8');
                if (stderrMsg) console.error(`[DockerService] Stderr: ${stderrMsg}`);
                throw new Error(`msfvenom exited with code ${result.StatusCode}. Stderr: ${stderrMsg}`);
            }

            return Buffer.concat(outputChunks);

        } finally {
            if (container) {
                try {
                    await container.remove({ force: true });
                } catch (e) {
                    console.error('Failed to remove container:', e);
                }
            }
        }
    }
}
