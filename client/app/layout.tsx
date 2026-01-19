import type { Metadata } from "next";
import { Inter } from "next/font/google";
import "./globals.css";
import { SidebarProvider, SidebarTrigger, SidebarInset } from "@/components/ui/sidebar"
import { AppSidebar } from "@/components/app-sidebar"

const inter = Inter({ subsets: ["latin"] });

export const metadata: Metadata = {
  title: "Crafting Table - Advanced Malware Development Toolkit",
  description: "Advanced malware development and obfuscation toolkit",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="fr" className="dark" suppressHydrationWarning>
      <body className={inter.className} suppressHydrationWarning>
        <SidebarProvider>
          <AppSidebar />
          <SidebarInset>
            <header className="flex h-16 shrink-0 items-center gap-2 border-b bg-background/50 backdrop-blur-md px-4 sticky top-0 z-10">
              <SidebarTrigger className="-ml-1" />
              <div className="w-[1px] h-4 bg-border mx-2"></div>
              <h1 className="text-sm font-bold tracking-wide uppercase text-emerald-500">Crafting Table</h1>
            </header>
            <main className="flex-1 p-6 md:p-8 pt-6">
              {children}
            </main>
          </SidebarInset>
        </SidebarProvider>
      </body>
    </html>
  );
}
