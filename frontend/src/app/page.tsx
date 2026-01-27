"use client"; // Required for hooks
import React, { useEffect, useState } from "react"; // Fixes ReferenceError
import AttackPathGraph from "@/components/dashboard/AttackPathGraph";
import ExplainPanel from "@/components/dashboard/ExplainPanel";
import Metrics from "@/components/dashboard/Metrics";
import FindingsTable from "@/components/dashboard/FindingsTable";
import ScanTerminal from "@/components/dashboard/ScanTerminal";
import Sidebar from "@/components/layout/Sidebar";

export default function Home() {
  const [graph, setGraph] = useState(null);
  const [logs, setLogs] = useState<string[]>([]);

  // SSE Connection for Logs
  useEffect(() => {
    const eventSource = new EventSource('http://localhost:8000/api/scan/stream');
    eventSource.onmessage = (event) => {
      if (event.data && event.data.trim()) {
        setLogs((prev) => [...prev, event.data]);
      }
    };
    eventSource.onerror = (err) => console.error('SSE Error:', err);
    return () => eventSource.close();
  }, []);

  useEffect(() => {
    let timer: any;
    const fetchData = async () => {
      try {
        const res = await fetch("http://localhost:8000/graph");
        const data = await res.json();
        setGraph(data);
      } catch (err) {
        console.error("Backend offline - Retrying...");
      } finally {
        // Recursive timeout prevents request stacking
        timer = setTimeout(fetchData, 3000);
      }
    };
    fetchData();
    return () => clearTimeout(timer); // Cleanup on unmount
  }, []);

  // LOADING STATE: Logic is now INSIDE the component
  if (!graph) return (
    <div className="h-screen w-screen bg-[#02030a] flex items-center justify-center font-mono">
      <div className="text-[#22d3ee] animate-pulse tracking-[1em] text-xs uppercase">
        Initializing_Astra_Core...
      </div>
    </div>
  );

  return (
    <div className="h-screen w-screen bg-[#02030a] text-[#eaeaf0] flex overflow-hidden cyber-grid p-2">
      <Sidebar />
      <main className="flex-1 flex flex-col gap-2 overflow-hidden px-2">
        <header className="h-10 glass flex items-center justify-between px-6 border-b border-[#22d3ee]/20">
          <div className="flex items-center gap-2">
            <div className="h-2 w-2 bg-[#22d3ee] pulse-glow rounded-full shadow-[0_0_10px_#22d3ee]" />
            <span className="text-[10px] font-black tracking-widest text-white uppercase italic">ASTRA_OS // SOC_COMMAND</span>
          </div>
        </header>

        <div className="flex-1 flex gap-2 overflow-hidden">
          {/* Main Visual Data Column */}
          <div className="flex-[2] flex flex-col gap-2 overflow-y-auto">
            {/* The Visual "Wow" Factor: Graph View */}
            <div className="flex-1 glass relative overflow-hidden bg-black/40 scanline">
              <AttackPathGraph initialData={graph} />
            </div>

            <div className="flex-1 glass overflow-hidden">
              <ScanTerminal logs={logs} />
            </div>
          </div>

          {/* AI Intelligence Sidebar */}
          <aside className="w-80 h-full">
            <ExplainPanel logs={logs} />
          </aside>
        </div>
      </main>
    </div>
  );
}