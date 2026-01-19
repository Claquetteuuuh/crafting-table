const http = require('http');
const fs = require('fs');

const payload = {
    name: "EarlyBirdTest",
    output: "exe",
    shellcode: "0xfc,0x48,0x83",
    injection_method: "early_bird",
    syscall_evasion: "none",
    anti_sandbox: [],
    anti_debug: [],
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

console.log('Testing Early Bird injection generation...');
const req = http.request(options, (res) => {
    let body = '';
    res.on('data', chunk => body += chunk);
    res.on('end', () => {
        try {
            const json = JSON.parse(body);
            if (json.source_code) {
                fs.writeFileSync('generated_earlybird.nim', json.source_code, 'utf8');
                console.log('✓ Generated: generated_earlybird.nim');
                console.log('✓ Size:', json.source_code.length, 'bytes');
                
                // Check for key Early Bird functions
                const hasCreateProcess = json.source_code.includes('CreateProcessW');
                const hasVirtualAllocEx = json.source_code.includes('VirtualAllocEx');
                const hasWriteProcessMemory = json.source_code.includes('WriteProcessMemory');
                const hasQueueUserAPC = json.source_code.includes('QueueUserAPC');
                const hasResumeThread = json.source_code.includes('ResumeThread');
                
                console.log('✓ CreateProcessW:', hasCreateProcess ? 'found' : 'MISSING');
                console.log('✓ VirtualAllocEx:', hasVirtualAllocEx ? 'found' : 'MISSING');
                console.log('✓ WriteProcessMemory:', hasWriteProcessMemory ? 'found' : 'MISSING');
                console.log('✓ QueueUserAPC:', hasQueueUserAPC ? 'found' : 'MISSING');
                console.log('✓ ResumeThread:', hasResumeThread ? 'found' : 'MISSING');
                
                if (hasCreateProcess && hasVirtualAllocEx && hasWriteProcessMemory && hasQueueUserAPC && hasResumeThread) {
                    console.log('\n✅ All Early Bird functions present!');
                } else {
                    console.log('\n❌ Some functions missing');
                }
            } else {
                console.error('❌ Error:', json);
            }
        } catch (e) {
            console.error('❌ Parse error:', e.message);
            console.error('Body:', body.substring(0, 500));
        }
    });
});

req.on('error', (e) => {
    console.error('❌ Request error:', e.message);
});

req.write(data);
req.end();
