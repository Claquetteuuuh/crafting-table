const http = require('http');
const fs = require('fs');

const scenarios = [
    {
        label: "RAW SHELLCODE",
        payload: {
            name: "RawTest",
            output: "exe",
            shellcode: "0xfc,0x48,0x83",
            injection_method: "fiber",
            syscall_evasion: "none"
        }
    },
    {
        label: "FULL EVASION + XOR",
        payload: {
            name: "HackerMode",
            output: "exe",
            shellcode: "0x12,0x34,0x56",
            xor_key: "0xAA,0xBB",
            injection_method: "fiber",
            syscall_evasion: "none",
            anti_sandbox: ["cpu_ram", "timing", "human_behavior"],
            anti_debug: ["is_debugger_present"]
        }
    }
];

let output = "";
let completed = 0;

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

    output += `\n\n=== SCENARIO: ${scenario.label} ===\n`;
    const req = http.request(options, (res) => {
        let body = '';
        res.on('data', chunk => body += chunk);
        res.on('end', () => {
            try {
                const json = JSON.parse(body);
                if (json.source_code) {
                    output += json.source_code + "\n";
                } else {
                    output += "ERROR: " + JSON.stringify(json, null, 2) + "\n";
                }
            } catch (e) {
                output += "PARSE ERROR: " + body + "\n";
            }
            
            completed++;
            if (completed === scenarios.length) {
                fs.writeFileSync('nim_preview.txt', output, 'utf8');
                console.log("✓ Preview written to nim_preview.txt");
                process.exit(0);
            }
        });
    });
    
    req.on('error', (e) => {
        output += `REQUEST ERROR: ${e.message}\n`;
        completed++;
        if (completed === scenarios.length) {
            fs.writeFileSync('nim_preview.txt', output, 'utf8');
            console.log("✓ Preview written to nim_preview.txt (with errors)");
            process.exit(1);
        }
    });
    
    req.write(data);
    req.end();
}

scenarios.forEach((s, i) => setTimeout(() => sendRequest(s), i * 1000));
