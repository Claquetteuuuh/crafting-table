'use client';

import {
    Dialog,
    DialogContent,
    DialogDescription,
    DialogFooter,
    DialogHeader,
    DialogTitle,
} from "@/components/ui/dialog"
import { Button } from "@/components/ui/button"
import { ScrollArea } from "@/components/ui/scroll-area"
import { Code, Check, Loader2, Play } from "lucide-react"

interface CodePreviewModalProps {
    isOpen: boolean;
    onOpenChange: (open: boolean) => void;
    sourceCode: string;
    onApprove: () => void;
    isCompiling?: boolean;
}

export function CodePreviewModal({
    isOpen,
    onOpenChange,
    sourceCode,
    onApprove,
    isCompiling = false,
}: CodePreviewModalProps) {
    return (
        <Dialog open={isOpen} onOpenChange={onOpenChange}>
            <DialogContent className="max-w-5xl h-[90vh] flex flex-col">
                <DialogHeader>
                    <DialogTitle className="flex items-center gap-2 text-xl">
                        <Code className="h-5 w-5 text-emerald-500" />
                        Vérification du Code Source
                    </DialogTitle>
                    <DialogDescription>
                        Examinez le code généré avant de lancer la compilation. Cette étape est critique pour la sécurité.
                    </DialogDescription>
                </DialogHeader>

                <div className="flex-1 min-h-0 border rounded-md bg-zinc-950 font-mono text-sm overflow-hidden">
                    <ScrollArea className="h-full p-4">
                        <pre className="text-zinc-300">
                            <code>{sourceCode}</code>
                        </pre>
                    </ScrollArea>
                </div>

                <DialogFooter className="mt-4 flex sm:justify-between items-center">
                    <div className="text-xs text-muted-foreground flex items-center gap-2">
                        <div className="h-2 w-2 rounded-full bg-emerald-500 animate-pulse"></div>
                        En attente d'approbation
                    </div>
                    <div className="flex gap-2">
                        <Button
                            variant="outline"
                            onClick={() => onOpenChange(false)}
                            disabled={isCompiling}
                        >
                            Annuler
                        </Button>
                        <Button
                            className="bg-emerald-500 hover:bg-emerald-600"
                            onClick={onApprove}
                            disabled={isCompiling}
                        >
                            {isCompiling ? (
                                <>
                                    <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                                    Compilation...
                                </>
                            ) : (
                                <>
                                    <Check className="mr-2 h-4 w-4" />
                                    Approuver & Compiler
                                </>
                            )}
                        </Button>
                    </div>
                </DialogFooter>
            </DialogContent>
        </Dialog>
    );
}
