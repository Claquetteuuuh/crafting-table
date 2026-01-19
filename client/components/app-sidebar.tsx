"use client"

import * as React from "react"
import {
    Folder,
    Settings,
    Shield,
    Zap,
} from "lucide-react"

import {
    Sidebar,
    SidebarContent,
    SidebarGroup,
    SidebarGroupContent,
    SidebarGroupLabel,
    SidebarHeader,
    SidebarMenu,
    SidebarMenuButton,
    SidebarMenuItem,
    SidebarRail,
} from "@/components/ui/sidebar"
import Image from "next/image"
import Link from "next/link"
import { usePathname } from "next/navigation"

// Menu items.
const items = [
    {
        title: "Usage Légal",
        url: "/",
        icon: Shield,
    },
    {
        title: "Shellcode Crafter",
        url: "/shellcode",
        icon: Zap,
    },
    {
        title: "Malware Crafter",
        url: "/creator",
        icon: Zap,
    },
    {
        title: "Configuration API",
        url: "/config",
        icon: Settings,
    },
]

export function AppSidebar({ ...props }: React.ComponentProps<typeof Sidebar>) {
    const pathname = usePathname();

    return (
        <Sidebar collapsible="icon" {...props}>
            <SidebarHeader>
                <div className="flex items-center gap-2 p-2">
                    <div className="flex h-10 w-10 items-center justify-center rounded-lg overflow-hidden border border-emerald-500/20 bg-emerald-500/5">
                        <Image
                            src="/logo.png"
                            alt="Crafting Table Logo"
                            width={40}
                            height={40}
                            className="object-cover"
                        />
                    </div>
                    <div className="grid flex-1 text-left text-sm leading-tight">
                        <span className="truncate font-bold tracking-wider text-emerald-500">CRAFTING-TABLE</span>
                        <span className="truncate text-[10px] text-muted-foreground uppercase opacity-70">Security Toolkit v1.0.0</span>
                    </div>
                </div>
            </SidebarHeader>
            <SidebarContent>
                <SidebarGroup>
                    <SidebarGroupLabel>Application</SidebarGroupLabel>
                    <SidebarGroupContent>
                        <SidebarMenu>
                            {items.map((item) => {
                                const isActive = pathname === item.url;
                                return (
                                    <SidebarMenuItem key={item.title}>
                                        <SidebarMenuButton
                                            asChild
                                            isActive={isActive}
                                            className={isActive ? "text-emerald-500 bg-emerald-500/10 hover:bg-emerald-500/20 hover:text-emerald-500" : ""}
                                        >
                                            <Link href={item.url}>
                                                <item.icon />
                                                <span>{item.title}</span>
                                            </Link>
                                        </SidebarMenuButton>
                                    </SidebarMenuItem>
                                )
                            })}
                        </SidebarMenu>
                    </SidebarGroupContent>
                </SidebarGroup>
            </SidebarContent>
            <SidebarRail />
        </Sidebar>
    )
}
