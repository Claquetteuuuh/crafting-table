const http = require('http');

const data = JSON.stringify({
    payload: 'linux/x64/shell_reverse_tcp',
    lhost: '127.0.0.1',
    lport: '4444',
    format: 'elf'
});

const options = {
    hostname: 'localhost',
    port: 3000,
    path: '/msfvenom-shellcode',
    method: 'POST',
    headers: {
        'Content-Type': 'application/json',
        'Content-Length': data.length
    }
};

console.log('Sending request to http://localhost:3000/msfvenom-shellcode...');

const req = http.request(options, (res) => {
    console.log(`STATUS: ${res.statusCode}`);
    console.log(`HEADERS: ${JSON.stringify(res.headers)}`);
    
    let chunks = [];
    res.on('data', (chunk) => {
        chunks.push(chunk);
    });

    res.on('end', () => {
        const bodyRaw = Buffer.concat(chunks).toString('utf8');
        console.log(`RESPONSE RAW: ${bodyRaw}`);
        
        try {
            const body = JSON.parse(bodyRaw);
            if (res.statusCode === 200 && body.shellcode) {
                const shellcode = Buffer.from(body.shellcode, 'base64');
                console.log(`SUCCESS: Shellcode generated.`);
                console.log(`SIZE: ${shellcode.length} bytes`);
                console.log(`HEX: ${shellcode.toString('hex')}`);
            } else {
                console.log('FAILURE: Invalid response or status code.');
            }
        } catch (e) {
            console.error('FAILURE: Could not parse JSON response:', e);
        }
    });
});

req.on('error', (e) => {
    console.error(`problem with request: ${e.message}`);
});

req.write(data);
req.end();
