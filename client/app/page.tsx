'use client';

import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { ShieldAlert, Scale, GraduationCap, Gavel } from "lucide-react"

export default function HomePage() {
  return (
    <div className="space-y-6 animate-in fade-in duration-500">
      <div className="space-y-2">
        <h2 className="text-3xl font-black tracking-tighter text-emerald-500 uppercase">Usage Légal & Éthique</h2>
        <p className="text-muted-foreground font-medium">
          Informations importantes concernant l&apos;utilisation de Crafting Table.
        </p>
      </div>

      <Alert variant="destructive" className="border-emerald-500/50 bg-emerald-500/5 text-emerald-500">
        <ShieldAlert className="h-5 w-5 !text-emerald-500" />
        <AlertTitle className="font-bold uppercase tracking-widest">Avertissement de Responsabilité</AlertTitle>
        <AlertDescription className="text-emerald-500/80">
          Crafting Table est un outil conçu exclusivement pour des tests de pénétration autorisés, la recherche en sécurité et l&apos;éducation.
        </AlertDescription>
      </Alert>
    </div>
  );
}
