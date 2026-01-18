const http = require('http');

const data = JSON.stringify({
    code: 'echo "Hello from Nim API!"\n',
    output: 'exe',
    flags: ['--app:console']
});

const options = {
    hostname: 'localhost',
    port: 3000,
    path: '/compile',
    method: 'POST',
    headers: {
        'Content-Type': 'application/json',
        'Content-Length': data.length
    }
};

console.log('Sending request to http://localhost:3000/compile...');

const req = http.request(options, (res) => {
    console.log(`STATUS: ${res.statusCode}`);
    
    let chunks = [];
    res.on('data', (chunk) => chunks.push(chunk));

    res.on('end', () => {
        const bodyRaw = Buffer.concat(chunks).toString('utf8');
        console.log(`RESPONSE RAW: ${bodyRaw}`);
        
        try {
            const body = JSON.parse(bodyRaw);
            if (res.statusCode === 200 && body.binary) {
                const binary = Buffer.from(body.binary, 'base64');
                console.log(`SUCCESS: Binary generated.`);
                console.log(`SIZE: ${binary.length} bytes`);
                console.log(`HEX prefix: ${binary.toString('hex').substring(0, 32)}...`);
                
                // Verify MZ header for EXE
                if (binary.toString('ascii').startsWith('MZ')) {
                    console.log('VALIDATION: Valid PE header (MZ) detected.');
                } else {
                    console.log('VALIDATION WARNING: No MZ header detected.');
                }
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
