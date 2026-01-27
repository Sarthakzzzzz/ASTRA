"use client";
import React, { useEffect, useRef, useState } from 'react';
import { Terminal } from 'lucide-react';

interface ScanTerminalProps {
    logs: string[];
}

export default function ScanTerminal({ logs }: ScanTerminalProps) {
    const terminalRef = useRef<HTMLDivElement>(null);

    // Auto-scroll to bottom
    useEffect(() => {
        if (terminalRef.current) {
            terminalRef.current.scrollTop = terminalRef.current.scrollHeight;
        }
    }, [logs]);

    return (
        <div className="glass h-full flex flex-col">
            <div className="flex items-center gap-2 border-b border-[#22d3ee]/20 p-3">
                <Terminal className="text-[#22d3ee]" size={16} />
                <span className="text-[10px] font-black tracking-widest text-white uppercase">
                    LIVE_SCAN_OUTPUT
                </span>
            </div>

            <div
                ref={terminalRef}
                className="flex-1 overflow-y-auto p-4 font-mono text-[10px] leading-relaxed bg-black/40"
            >
                {logs.length === 0 ? (
                    <div className="text-[#22d3ee]/40 italic">Waiting for scan to start...</div>
                ) : (
                    logs.map((log, i) => (
                        <div key={i} className="text-green-400/90">
                            {log}
                        </div>
                    ))
                )}
            </div>
        </div>
    );
}
