const http = require('http');
const fs = require('fs');

const source = fs.readFileSync('generated_payload.nim', 'utf8');

const payload = {
    code: source,  // Changed from 'source' to 'code'
    output: "exe",
    arch: "amd64",
    flags: []
};

const data = JSON.stringify(payload);
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

console.log('Testing compilation...');

const req = http.request(options, (res) => {
    let body = '';
    res.on('data', chunk => body += chunk);
    res.on('end', () => {
        console.log('Status:', res.statusCode);
        if (res.statusCode !== 200) {
            console.error('Response:', body);
            process.exit(1);
        }
        try {
            const json = JSON.parse(body);
            if (json.error) {
                console.error('❌ Compilation failed:');
                console.error('Error:', json.error);
                console.error('Details:', json.details);
                process.exit(1);
            }
            console.log('✅ Compilation successful!');
            console.log('Binary size:', Buffer.from(json.binary, 'base64').length, 'bytes');
            
            fs.writeFileSync('payload.exe', Buffer.from(json.binary, 'base64'));
            console.log('✅ Saved to: payload.exe');
        } catch (e) {
            console.error('❌ Parse error:', e.message);
            console.error('Body:', body.substring(0, 1000));
            process.exit(1);
        }
    });
});

req.on('error', (e) => {
    console.error('❌ Request error:', e.message);
    process.exit(1);
});

req.write(data);
req.end();
