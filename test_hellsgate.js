const http = require('http');
const fs = require('fs');

const payload = {
    name: "HellsGateTest",
    output: "exe",
    shellcode: "0xfc,0x48,0x83",
    injection_method: "fiber",
    syscall_evasion: "hells_gate",
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

console.log('Testing Hell\'s Gate + Fiber injection...');
const req = http.request(options, (res) => {
    let body = '';
    res.on('data', chunk => body += chunk);
    res.on('end', () => {
        try {
            const json = JSON.parse(body);
            if (json.source_code) {
                fs.writeFileSync('generated_hellsgate.nim', json.source_code, 'utf8');
                console.log('✓ Generated: generated_hellsgate.nim');
                console.log('✓ Size:', json.source_code.length, 'bytes');
                
                // Check for Hell's Gate components
                const checks = {
                    'HG_TABLE_ENTRY': json.source_code.includes('HG_TABLE_ENTRY'),
                    'djb2_hash': json.source_code.includes('djb2_hash'),
                    'GetPEBAsm64': json.source_code.includes('GetPEBAsm64'),
                    'getSyscall': json.source_code.includes('getSyscall'),
                    'NtAllocateVirtualMemory': json.source_code.includes('NtAllocateVirtualMemory'),
                    'NtProtectVirtualMemory': json.source_code.includes('NtProtectVirtualMemory'),
                    'ConvertThreadToFiber': json.source_code.includes('ConvertThreadToFiber'),
                    'SwitchToFiber': json.source_code.includes('SwitchToFiber'),
                    'Hell\'s Gate comment': json.source_code.includes('Hell\'s Gate')
                };
                
                console.log('\n=== Component Check ===');
                let allPresent = true;
                for (const [name, present] of Object.entries(checks)) {
                    const status = present ? '✓' : '✗';
                    console.log(`${status} ${name}: ${present ? 'found' : 'MISSING'}`);
                    if (!present) allPresent = false;
                }
                
                if (allPresent) {
                    console.log('\n✅ All Hell\'s Gate components present!');
                } else {
                    console.log('\n❌ Some components missing');
                }
                
                // Count lines
                const lines = json.source_code.split('\n').length;
                console.log(`\nTotal lines: ${lines}`);
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
