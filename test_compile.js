const http = require('http');
const fs = require('fs');

// First generate the payload
const generatePayload = {
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

const genData = JSON.stringify(generatePayload);
const genOptions = {
    hostname: 'localhost',
    port: 3000,
    path: '/generate-payload',
    method: 'POST',
    headers: {
        'Content-Type': 'application/json',
        'Content-Length': genData.length
    }
};

console.log('Step 1: Generating payload...');
const genReq = http.request(genOptions, (res) => {
    let body = '';
    res.on('data', chunk => body += chunk);
    res.on('end', () => {
        try {
            const json = JSON.parse(body);
            if (!json.source_code) {
                console.error('❌ Generation failed:', json);
                process.exit(1);
            }
            
            console.log('✓ Payload generated');
            
            // Now compile it
            const compilePayload = {
                source: json.source_code,
                output: "exe",
                arch: "amd64"
            };
            
            const compData = JSON.stringify(compilePayload);
            const compOptions = {
                hostname: 'localhost',
                port: 3000,
                path: '/compile',
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Content-Length': compData.length
                }
            };
            
            console.log('Step 2: Compiling...');
            const compReq = http.request(compOptions, (compRes) => {
                let compBody = '';
                compRes.on('data', chunk => compBody += chunk);
                compRes.on('end', () => {
                    try {
                        const compJson = JSON.parse(compBody);
                        if (compJson.error) {
                            console.error('❌ Compilation failed:', compJson);
                            process.exit(1);
                        }
                        console.log('✓ Compilation successful!');
                        console.log('✓ Binary size:', compJson.binary.length, 'bytes (base64)');
                        console.log('✓ Actual size:', Buffer.from(compJson.binary, 'base64').length, 'bytes');
                        
                        // Save binary
                        fs.writeFileSync('compiled_payload.exe', Buffer.from(compJson.binary, 'base64'));
                        console.log('✓ Saved to: compiled_payload.exe');
                    } catch (e) {
                        console.error('❌ Parse error:', e.message);
                        console.error('Response:', compBody);
                        process.exit(1);
                    }
                });
            });
            
            compReq.on('error', (e) => {
                console.error('❌ Compile request error:', e.message);
                process.exit(1);
            });
            
            compReq.write(compData);
            compReq.end();
            
        } catch (e) {
            console.error('❌ Parse error:', e.message);
            console.error('Response:', body);
            process.exit(1);
        }
    });
});

genReq.on('error', (e) => {
    console.error('❌ Generate request error:', e.message);
    process.exit(1);
});

genReq.write(genData);
genReq.end();
