const express = require('express');
const Docker = require('dockerode');
const stream = require('stream');

const app = express();
const docker = new Docker({ socketPath: '/var/run/docker.sock' });
const port = 3000;

app.use(express.json());

app.post('/msfvenom-shellcode', async (req, res) => {
    try {
        const { payload, lhost, lport, format, badchars, encoder, iterations } = req.body;

        if (!payload || !lhost || !lport) {
            return res.status(400).json({ error: 'Missing required parameters: payload, lhost, lport' });
        }

        console.log(`Generating shellcode: ${payload} LHOST=${lhost} LPORT=${lport}`);

        // Construct msfvenom command arguments
        const cmd = ['msfvenom', '-p', payload, `LHOST=${lhost}`, `LPORT=${lport}`];
        
        if (format) cmd.push('-f', format);
        if (badchars) cmd.push('-b', badchars);
        if (encoder) cmd.push('-e', encoder);
        if (iterations) cmd.push('-i', iterations.toString());

        // Stream to capture stdout
        const logStream = new stream.PassThrough();
        let output = Buffer.alloc(0);

        logStream.on('data', (chunk) => {
            output = Buffer.concat([output, chunk]);
        });

        // Create and run the container
        const container = await docker.createContainer({
            Image: 'metasploitframework/metasploit-framework',
            Cmd: cmd,
            Tty: false,
            AttachStdout: true,
            AttachStderr: true // Capture stderr as well for debugging errors
        });

        const streamData = await container.attach({ stream: true, stdout: true, stderr: true });
        container.modem.demuxStream(streamData, logStream, process.stderr); // Send stderr to node's stderr

        await container.start();
        
        // Wait for container to exit
        const data = await container.wait();

        // Cleanup
        await container.remove();

        if (data.StatusCode !== 0) {
            console.error('msfvenom failed with status:', data.StatusCode);
            return res.status(500).json({ error: 'Generation failed', details: 'Check backend logs for msfvenom errors.' });
        }

        // Return the binary or text data
        // If format implies binary (like 'elf', 'exe', 'raw'), we send buffer.
        // For 'py', 'c', etc it's text.
        // For simplicity, we send the raw buffer. Client can save it.
        
        res.setHeader('Content-Type', 'application/octet-stream');
        res.setHeader('Content-Disposition', `attachment; filename="shellcode.${format || 'raw'}"`);
        res.send(output);

    } catch (error) {
        console.error('Error generating shellcode:', error);
        res.status(500).json({ error: 'Internal server error', details: error.message });
    }
});

app.listen(port, () => {
    console.log(`MSFVenom API listening at http://localhost:${port}`);
});
