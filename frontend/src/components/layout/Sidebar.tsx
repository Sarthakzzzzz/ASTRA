"use client";
import React, { useState, useEffect } from "react";

interface Scanner {
    name: string;
    enabled: boolean;
}

export default function Sidebar() {
    const [target, setTarget] = useState("");
    const [mode, setMode] = useState("dynamic");
    const [loading, setLoading] = useState(false);
    const [scanners, setScanners] = useState<Scanner[]>([]);
    const [selectedScanners, setSelectedScanners] = useState<Set<string>>(new Set());

    useEffect(() => {
        // Fetch available scanners on mount
        fetch("http://localhost:8000/api/scanners")
            .then((res) => res.json())
            .then((data: Scanner[]) => {
                setScanners(data);
                // Default to all enabled scanners, or just nmap/nuclei if others disabled
                // For now, let's select all that are 'enabled' by default in backend
                // OR select ALL by default as per previous behavior
                const initial = new Set(data.map(s => s.name));
                setSelectedScanners(initial);
            })
            .catch((err) => console.error("Failed to fetch scanners:", err));
    }, []);

    const toggleScanner = (name: string) => {
        const newSet = new Set(selectedScanners);
        if (newSet.has(name)) {
            newSet.delete(name);
        } else {
            newSet.add(name);
        }
        setSelectedScanners(newSet);
    };

    const handleRun = async () => {
        if (!target) return;
        setLoading(true);
        try {
            // Convert Set to comma-separated string
            const scannersList = Array.from(selectedScanners).join(",");

            const res = await fetch("http://localhost:8000/api/scan", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ target, mode, scanners: scannersList }),
            });
            const data = await res.json();
            alert(data.message || data.error);
        } catch (err) {
            alert("Failed to reach scanner backend.");
        } finally {
            setLoading(false);
        }
    };

    return (
        <div className="w-80 glass p-6 text-white border-r border-[#22d3ee]/20 flex flex-col h-full overflow-hidden">
            <h2 className="text-xs font-black tracking-widest text-[#22d3ee] mb-6 uppercase italic flex-shrink-0">
                ASTRA_ORCHESTRATOR // CONFIG
            </h2>

            <div className="space-y-6 flex-grow overflow-y-auto pr-2 custom-scrollbar">
                <div>
                    <label className="text-[10px] text-[#22d3ee]/60 uppercase tracking-tighter">Target_Node</label>
                    <input
                        value={target}
                        onChange={(e) => setTarget(e.target.value)}
                        className="w-full mt-1 bg-black/40 border border-[#22d3ee]/20 p-2 text-xs focus:border-[#22d3ee] outline-none transition-colors"
                        placeholder="scanme.nmap.org"
                    />
                </div>

                <div>
                    <p className="text-[10px] text-[#22d3ee]/60 uppercase tracking-tighter mb-2">Operation_Mode</p>
                    <div className="flex gap-4">
                        <label className="flex items-center gap-2 cursor-pointer group">
                            <div className={`w-3 h-3 border ${mode === 'dynamic' ? 'bg-[#22d3ee] border-[#22d3ee]' : 'border-[#22d3ee]/40'} transition-all`}></div>
                            <input
                                type="radio"
                                name="mode"
                                checked={mode === "dynamic"}
                                onChange={() => setMode("dynamic")}
                                className="hidden"
                            />
                            <span className="text-[10px] uppercase group-hover:text-[#22d3ee] transition-colors">Dynamic</span>
                        </label>
                        <label className="flex items-center gap-2 cursor-pointer group">
                            <div className={`w-3 h-3 border ${mode === 'static' ? 'bg-[#22d3ee] border-[#22d3ee]' : 'border-[#22d3ee]/40'} transition-all`}></div>
                            <input
                                type="radio"
                                name="mode"
                                checked={mode === "static"}
                                onChange={() => setMode("static")}
                                className="hidden"
                            />
                            <span className="text-[10px] uppercase group-hover:text-[#22d3ee] transition-colors">Static</span>
                        </label>
                    </div>
                </div>

                <div>
                    <p className="text-[10px] text-[#22d3ee]/60 uppercase tracking-tighter mb-2">Active_Modules</p>
                    <div className="space-y-1 bg-[#22d3ee]/5 p-2 border border-[#22d3ee]/10">
                        {scanners.length === 0 ? (
                            <div className="text-[9px] text-gray-500 italic">Connecting to module registry...</div>
                        ) : (
                            scanners.map((s) => (
                                <label key={s.name} className="flex items-center gap-2 cursor-pointer hover:bg-[#22d3ee]/10 p-1 transition-colors">
                                    <input
                                        type="checkbox"
                                        checked={selectedScanners.has(s.name)}
                                        onChange={() => toggleScanner(s.name)}
                                        className="accent-[#22d3ee]"
                                    />
                                    <span className="text-[10px] font-mono lowercase">{s.name}</span>
                                </label>
                            ))
                        )}
                    </div>
                </div>
            </div>

            <div className="pt-4 flex-shrink-0">
                <div className="mb-4 p-3 bg-[#22d3ee]/5 border border-[#22d3ee]/10 text-[9px] font-mono leading-relaxed">
                    <div className="flex justify-between">
                        <span className="text-[#22d3ee]/60">MODULES_SELECTED:</span>
                        <span className="text-[#22d3ee]">{selectedScanners.size}</span>
                    </div>
                </div>

                <button
                    onClick={handleRun}
                    disabled={loading || !target || selectedScanners.size === 0}
                    className={`w-full border border-[#22d3ee] py-3 text-[10px] uppercase tracking-[0.2em] font-bold hover:bg-[#22d3ee] hover:text-black transition-all duration-300 ${loading || !target || selectedScanners.size === 0 ? 'opacity-50 cursor-not-allowed' : 'pulse-glow'}`}
                >
                    {loading ? "INITIALIZING..." : "EXECUTE_SCAN"}
                </button>
            </div>
        </div>
    );
}
