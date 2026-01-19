import { Request, Response } from 'express';

interface IATFunction {
    dll: string;
    function_name: string;
    description: string;
}

export class IATController {
    
    constructor() {
    }
    
    listFunctions(req: Request, res: Response): void {
        const functions: IATFunction[] = [
            // User32.dll - Window management functions
            { dll: "user32", function_name: "GetActiveWindow", description: "Gets the active window" },
            { dll: "user32", function_name: "GetSystemMetrics", description: "Retrieves system metrics" },
            { dll: "user32", function_name: "IsWindowVisible", description: "Checks if window is visible" },
            { dll: "user32", function_name: "MessageBoxW", description: "Displays a message box" },

            // Kernel32.dll - System functions
            { dll: "kernel32", function_name: "GetTickCount", description: "Gets milliseconds since boot" },
            { dll: "kernel32", function_name: "GetTickCount64", description: "Gets milliseconds since boot (64-bit)" },
            { dll: "kernel32", function_name: "GetFileType", description: "Gets file type" },
            { dll: "kernel32", function_name: "GetCurrentProcessId", description: "Gets current process ID" },
            { dll: "kernel32", function_name: "GetCurrentThreadId", description: "Gets current thread ID" },

            // Advapi32.dll - Registry/security functions
            { dll: "advapi32", function_name: "RegCloseKey", description: "Closes registry key" },
            { dll: "advapi32", function_name: "RegOpenKeyExW", description: "Opens registry key" },
            { dll: "advapi32", function_name: "RegQueryValueExW", description: "Queries registry value" },

            // Shell32.dll - Shell functions
            { dll: "shell32", function_name: "SHGetFolderPathW", description: "Gets special folder path" },

            // Ws2_32.dll - Network functions
            { dll: "ws2_32", function_name: "WSAStartup", description: "Initializes Winsock" },
            { dll: "ws2_32", function_name: "WSACleanup", description: "Cleans up Winsock" },
            { dll: "ws2_32", function_name: "gethostname", description: "Gets host name" },
        ];

        res.json({
            status: "success",
            count: functions.length,
            functions: functions
        });
    }
}
