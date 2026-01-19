'use client';

import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { Button } from "@/components/ui/button"
import { Settings, Info } from "lucide-react"
import { useState } from 'react';

export default function ConfigPage() {
    const [apiUrl, setApiUrl] = useState('http://localhost:3000/api');

    return (
        <div className="space-y-6">
            <div>
                <h2 className="text-3xl font-bold tracking-tight">Configuration API</h2>
                <p className="text-muted-foreground">
                    Configurez les paramètres de connexion à l&apos;API backend.
                </p>
            </div>

            <div className="max-w-2xl">
                <Card>
                    <CardHeader>
                        <CardTitle className="flex items-center gap-2">
                            <Settings className="h-5 w-5 text-gray-500" />
                            Paramètres API
                        </CardTitle>
                        <CardDescription>Endpoint de connexion au serveur C2</CardDescription>
                    </CardHeader>
                    <CardContent className="space-y-6">
                        <div className="space-y-2">
                            <label className="text-sm font-medium">URL de l&apos;API</label>
                            <Input
                                value={apiUrl}
                                onChange={(e) => setApiUrl(e.target.value)}
                                placeholder="http://localhost:3000/api"
                            />
                        </div>

                        <div className="rounded-md bg-blue-500/10 p-4 border border-blue-500/20 flex items-start gap-4">
                            <Info className="h-5 w-5 text-blue-400 mt-0.5" />
                            <div className="text-sm">
                                <p className="font-semibold text-blue-400 mb-1">Information</p>
                                <p className="text-gray-400">
                                    L&apos;URL de l&apos;API est configurée via la variable d&apos;environnement{' '}
                                    <code className="bg-black/30 px-1 py-0.5 rounded text-emerald-400 font-mono">
                                        NEXT_PUBLIC_API_URL
                                    </code>
                                    . <br />
                                    Pour la modifier de façon permanente, éditez le fichier <code className="bg-black/30 px-1 py-0.5 rounded text-emerald-400 font-mono">.env.local</code>.
                                </p>
                            </div>
                        </div>

                        <div>
                            <h4 className="text-sm font-semibold mb-3">Endpoints Disponibles</h4>
                            <div className="space-y-2">
                                {[
                                    { method: 'POST', path: '/msfvenom-shellcode' },
                                    { method: 'POST', path: '/generate-payload' },
                                    { method: 'POST', path: '/compile' },
                                    { method: 'GET', path: '/iat-functions' },
                                ].map((ep) => (
                                    <div key={ep.path} className="flex items-center gap-2 text-sm font-mono bg-muted p-2 rounded">
                                        <span className={`px-2 py-0.5 rounded text-xs font-bold ${ep.method === 'GET' ? 'bg-blue-500/20 text-blue-400' : 'bg-green-500/20 text-green-400'}`}>
                                            {ep.method}
                                        </span>
                                        <span className="text-muted-foreground">{ep.path}</span>
                                    </div>
                                ))}
                            </div>
                        </div>

                        <Button className="w-full">Tester la Connexion</Button>
                    </CardContent>
                </Card>
            </div>
        </div>
    );
}
