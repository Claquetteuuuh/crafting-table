const http = require('http');
const fs = require('fs');

const testCases = [
    {
        name: "FiberInjection",
        payload: {
            name: "FiberTest",
            output: "exe",
            shellcode: "0xfc,0x48,0x83",
            injection_method: "fiber",
            syscall_evasion: "none",
            anti_sandbox: [],
            anti_debug: [],
            iat_spoofing: []
        }
    },
    {
        name: "ThreadInjection",
        payload: {
            name: "ThreadTest",
            output: "exe",
            shellcode: "0xfc,0x48,0x83",
            injection_method: "thread",
            syscall_evasion: "none",
            anti_sandbox: [],
            anti_debug: [],
            iat_spoofing: []
        }
    }
];

function testPayload(testCase, callback) {
    const data = JSON.stringify(testCase.payload);
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

    console.log(`\n=== Testing: ${testCase.name} ===`);
    const req = http.request(options, (res) => {
        let body = '';
        res.on('data', chunk => body += chunk);
        res.on('end', () => {
            try {
                const json = JSON.parse(body);
                if (json.source_code) {
                    const filename = `generated_${testCase.name.toLowerCase()}.nim`;
                    fs.writeFileSync(filename, json.source_code, 'utf8');
                    console.log(`✓ Generated: ${filename}`);
                    console.log(`✓ Size: ${json.source_code.length} bytes`);
                    
                    // Check for key injection functions
                    if (testCase.payload.injection_method === 'fiber') {
                        if (json.source_code.includes('ConvertThreadToFiber') && 
                            json.source_code.includes('CreateFiber') &&
                            json.source_code.includes('SwitchToFiber')) {
                            console.log('✓ Fiber injection functions found');
                        } else {
                            console.log('❌ Missing Fiber injection functions');
                        }
                    } else if (testCase.payload.injection_method === 'thread') {
                        if (json.source_code.includes('CreateThread') && 
                            json.source_code.includes('WaitForSingleObject')) {
                            console.log('✓ Thread injection functions found');
                        } else {
                            console.log('❌ Missing Thread injection functions');
                        }
                    }
                    
                    if (callback) callback();
                } else {
                    console.error('❌ Error:', json);
                    if (callback) callback();
                }
            } catch (e) {
                console.error('❌ Parse error:', e.message);
                if (callback) callback();
            }
        });
    });

    req.on('error', (e) => {
        console.error('❌ Request error:', e.message);
        if (callback) callback();
    });

    req.write(data);
    req.end();
}

// Run tests sequentially
let currentTest = 0;
function runNext() {
    if (currentTest < testCases.length) {
        testPayload(testCases[currentTest], () => {
            currentTest++;
            setTimeout(runNext, 500);
        });
    } else {
        console.log('\n✓ All tests completed');
    }
}

runNext();
