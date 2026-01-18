const http = require('http');

const validPayload = {
    name: "MalwareTest",
    output: "exe",
    shellcode: "0xfc,0x48,0x83", // Minimal fake shellcode
    // shellcode_url: "http://malicious.com/shellcode.bin", // Should not be present if shellcode is present
    injection_method: "early_bird",
    syscall_evasion: "hells_gate",
    anti_sandbox: ["cpu_ram", "human_behavior"],
    anti_debug: ["is_debugger_present"],
    iat_spoofing: [{ dll: "kernel32", functionName: "VirtualAlloc" }]
};

const invalidPayload = {
    name: "InvalidMalware",
    output: "exe",
    // Missing shellcode AND shellcode_url -> Should fail
    injection_method: "invalid_method", // Should fail enum
    syscall_evasion: "none"
};

function sendRequest(payload, label) {
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

    console.log(`\n--- Sending ${label} ---`);
    const req = http.request(options, (res) => {
        let body = '';
        res.on('data', chunk => body += chunk);
        res.on('end', () => {
            console.log(`STATUS: ${res.statusCode}`);
            try {
                const json = JSON.parse(body);
                console.log(JSON.stringify(json, null, 2));
            } catch (e) {
                console.log("Raw body:", body);
            }
        });
    });
    
    req.write(data);
    req.end();
}

// Run tests
setTimeout(() => sendRequest(validPayload, "VALID REQUEST"), 1000);
setTimeout(() => sendRequest(invalidPayload, "INVALID REQUEST"), 3000);
