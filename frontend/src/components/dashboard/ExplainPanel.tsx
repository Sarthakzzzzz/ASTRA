"use client";
import { useState, useEffect } from "react";
import { Brain, MessageSquare } from "lucide-react";
import AIChat from "./AIChat";

interface ExplainPanelProps {
  logs: string[];
}

export default function ExplainPanel({ logs }: ExplainPanelProps) {
  const [activeTab, setActiveTab] = useState<'reasoning' | 'chat'>('reasoning');
  const [reasoning, setReasoning] = useState("Waiting for active scan analysis...");

  useEffect(() => {
    const fetchReasons = async () => {
      try {
        const res = await fetch("http://localhost:8000/ai/reasoning");
        const data = await res.json();
        if (data.reasoning) setReasoning(data.reasoning);
      } catch (e) {
        // Silent fail for polling
      }
    };

    fetchReasons();
    const interval = setInterval(fetchReasons, 3000);
    return () => clearInterval(interval);
  }, []);

  return (
    <div className="glass h-full flex flex-col relative overflow-hidden scanline">
      {/* Header / Tabs */}
      <div className="flex border-b border-white/10">
        <button
          onClick={() => setActiveTab('reasoning')}
          className={`flex-1 flex items-center justify-center gap-2 py-3 px-4 text-xs font-black tracking-widest uppercase transition-colors ${activeTab === 'reasoning'
              ? 'bg-[#22d3ee]/20 text-[#22d3ee] border-b-2 border-[#22d3ee]'
              : 'text-gray-500 hover:text-gray-300 hover:bg-white/5'
            }`}
        >
          <Brain size={16} />
          <span>Reasoning</span>
        </button>
        <button
          onClick={() => setActiveTab('chat')}
          className={`flex-1 flex items-center justify-center gap-2 py-3 px-4 text-xs font-black tracking-widest uppercase transition-colors ${activeTab === 'chat'
              ? 'bg-[#22d3ee]/20 text-[#22d3ee] border-b-2 border-[#22d3ee]'
              : 'text-gray-500 hover:text-gray-300 hover:bg-white/5'
            }`}
        >
          <MessageSquare size={16} />
          <span>AI Chat</span>
        </button>
      </div>

      {/* Content Area */}
      <div className="flex-1 overflow-auto p-4">
        {activeTab === 'reasoning' ? (
          <div className="space-y-4 h-full flex flex-col">
            <div className="bg-cyan-950/20 p-4 border border-[#22d3ee]/10 rounded text-xs text-cyan-100/80 leading-relaxed flex-1 overflow-y-auto font-mono">
              {reasoning}
            </div>
            <button className="w-full py-3 bg-[#22d3ee] text-black font-black text-xs uppercase tracking-widest hover:bg-cyan-400 transition-all shrink-0">
              EXECUTE_REMEDIATION
            </button>
          </div>
        ) : (
          <AIChat logs={logs} />
        )}
      </div>
    </div>
  );
}