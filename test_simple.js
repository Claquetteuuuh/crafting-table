const http = require('http');
const fs = require('fs');

const payload = {
    name: "FullEvasionTest",
    output: "exe",
    shellcode: "0xfc,0x48,0x83",
    xor_key: "0xAA,0xBB",
    injection_method: "fiber",
    syscall_evasion: "none",
    anti_sandbox: ["cpu_ram", "timing", "human_behavior"],
    anti_debug: ["is_debugger_present"]
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

console.log('Sending request to API...');
const req = http.request(options, (res) => {
    let body = '';
    res.on('data', chunk => body += chunk);
    res.on('end', () => {
        try {
            const json = JSON.parse(body);
            if (json.source_code) {
                fs.writeFileSync('generated_payload.nim', json.source_code, 'utf8');
                console.log('\n✓ Generated Nim code saved to: generated_payload.nim');
                console.log(`✓ File size: ${json.source_code.length} bytes`);
                console.log('\n--- PREVIEW (first 80 lines) ---');
                const lines = json.source_code.split('\n');
                console.log(lines.slice(0, 80).join('\n'));
                if (lines.length > 80) {
                    console.log(`\n... (${lines.length - 80} more lines)`);
                }
            } else {
                console.error('ERROR:', JSON.stringify(json, null, 2));
            }
        } catch (e) {
            console.error('Parse error:', e.message);
            console.error('Raw body:', body);
        }
    });
});

req.on('error', (e) => {
    console.error('Request error:', e.message);
});

req.write(data);
req.end();
