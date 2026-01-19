'use client';

import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Input } from "@/components/ui/input"
import { Button } from "@/components/ui/button"
import { Search, Plus, Download } from "lucide-react"
import Link from "next/link"

interface Malware {
  id: string;
  name: string;
  format: string;
  method: string;
  evasion: string;
  buildDate: string;
  status: "ready" | "failed";
}

const mockMalwares: Malware[] = [];

export default function HomePage() {
  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between space-y-2">
        <div>
          <h2 className="text-3xl font-bold tracking-tight">Mes Malwares</h2>
          <p className="text-muted-foreground">
            Gérez vos binaires générés et surveillez leur statut.
          </p>
        </div>
        <div className="flex items-center space-x-2">
          <Link href="/creator">
            <Button className="bg-emerald-500 hover:bg-emerald-600">
              <Plus className="mr-2 h-4 w-4" /> Nouveau Malware
            </Button>
          </Link>
        </div>
      </div>

      <div className="flex items-center space-x-2">
        <div className="relative w-full max-w-sm">
          <Search className="absolute left-2.5 top-2.5 h-4 w-4 text-muted-foreground" />
          <Input type="search" placeholder="Rechercher un binaire..." className="pl-8" />
        </div>
      </div>

      <Card>
        <CardHeader className="px-6 py-4 border-b">
          <CardTitle className="text-base font-medium">Binares Récents</CardTitle>
        </CardHeader>
        <CardContent className="p-0">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="w-[300px]">Nom du Binaire</TableHead>
                <TableHead>Format</TableHead>
                <TableHead>Méthode</TableHead>
                <TableHead>Evasion</TableHead>
                <TableHead>Build Date</TableHead>
                <TableHead className="text-right">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {mockMalwares.map((malware) => (
                <TableRow key={malware.id} className="cursor-pointer hover:bg-muted/50">
                  <TableCell className="font-medium">
                    <div className="flex items-center gap-2">
                      <div className="h-8 w-8 rounded bg-emerald-500/10 flex items-center justify-center text-emerald-500">
                        ⚡
                      </div>
                      {malware.name}
                    </div>
                  </TableCell>
                  <TableCell>
                    <Badge variant="secondary" className="font-mono">
                      {malware.format}
                    </Badge>
                  </TableCell>
                  <TableCell>{malware.method}</TableCell>
                  <TableCell>{malware.evasion}</TableCell>
                  <TableCell className="text-muted-foreground">{malware.buildDate}</TableCell>
                  <TableCell className="text-right">
                    <Button variant="ghost" size="icon">
                      <Download className="h-4 w-4" />
                    </Button>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </div>
  );
}
