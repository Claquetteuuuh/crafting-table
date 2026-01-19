const http = require('http');

const payload = {
    name: "TestCompile",
    output: "exe",
    shellcode: "0xfc,0x48,0x83",
    xor_key: "0xAA",
    injection_method: "fiber",
    syscall_evasion: "none",
    anti_sandbox: [],
    anti_debug: ["is_debugger_present"],
    iat_spoofing: []
};

const data = JSON.stringify(payload);
const options = {
    hostname: 'localhost',
    port: 3000,
    path: '/generate-payload',
    method: 'POST',
    headers: {
        'Content-Type': 'application/json',
        'Content-Length': data.length
    }
};

console.log('Sending:', JSON.stringify(payload, null, 2));
const req = http.request(options, (res) => {
    let body = '';
    res.on('data', chunk => body += chunk);
    res.on('end', () => {
        console.log('Status:', res.statusCode);
        console.log('Response:', body);
    });
});

req.on('error', (e) => {
    console.error('Error:', e.message);
});

req.write(data);
req.end();
