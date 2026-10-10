import React, { useState } from 'react';
import { Threat, Incident } from '../../types/cyberguard';
import { useCyberGuard } from '../../context/CyberGuardContext';
import { Play, Check, AlertTriangle, ShieldCheck, ExternalLink, RefreshCw } from 'lucide-react';

interface ResponsePanelProps {
  threat: Threat;
  onExecuted?: (incident: Incident) => void;
  className?: string;
}

export const ResponsePanel: React.FC<ResponsePanelProps> = ({
  threat,
  onExecuted,
  className = '',
}) => {
  const { executeSOAR, setSelectedIncident, setActiveTab } = useCyberGuard();
  const [isExecuting, setIsExecuting] = useState(false);
  const [executedIncident, setExecutedIncident] = useState<Incident | null>(null);

  const handleExecute = () => {
    setIsExecuting(true);
    setTimeout(() => {
      const inc = executeSOAR(threat);
      setExecutedIncident(inc);
      setIsExecuting(false);
      if (onExecuted) onExecuted(inc);
    }, 700);
  };

  const handleViewIncident = (incident: Incident) => {
    setSelectedIncident(incident);
    setActiveTab('dashboard');
  };

  return (
    <div className={`p-4 rounded-xl border border-slate-800 bg-slate-900/80 backdrop-blur-md ${className}`}>
      <div className="flex items-center justify-between pb-3 border-b border-slate-800 mb-3">
        <div className="flex items-center space-x-2">
          <div className="w-2.5 h-2.5 rounded-full bg-cyan-400 animate-ping" />
          <h4 className="text-xs font-mono font-bold uppercase tracking-wider text-slate-200">
            Automated SOAR Response Engine
          </h4>
        </div>
        <span className="text-[11px] font-mono text-cyan-400 px-2 py-0.5 rounded bg-cyan-500/10 border border-cyan-500/20">
          Autonomous Playbook Active
        </span>
      </div>

      {!executedIncident ? (
        <div className="space-y-3">
          <p className="text-xs text-slate-300 font-sans">
            AI recommends automated containment for this <span className="font-semibold text-rose-400">{threat.severity}</span> threat. Click below to execute immediate firewall rules, session revocations, and incident logging.
          </p>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs font-mono text-slate-300">
            <div className="flex items-center space-x-1.5 text-slate-400">
              <span className="text-cyan-400">▹</span>
              <span>Block Destination URL & DNS</span>
            </div>
            <div className="flex items-center space-x-1.5 text-slate-400">
              <span className="text-cyan-400">▹</span>
              <span>Quarantine Phishing Payload</span>
            </div>
            <div className="flex items-center space-x-1.5 text-slate-400">
              <span className="text-cyan-400">▹</span>
              <span>Revoke Affected User Sessions</span>
            </div>
            <div className="flex items-center space-x-1.5 text-slate-400">
              <span className="text-cyan-400">▹</span>
              <span>Create Official SOC Incident Ticket</span>
            </div>
          </div>

          <div className="flex items-center space-x-3 pt-2">
            <button
              onClick={handleExecute}
              disabled={isExecuting}
              className="flex-1 flex items-center justify-center space-x-2 py-2.5 px-4 rounded-lg bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-slate-950 font-bold text-xs uppercase tracking-wider font-mono shadow-[0_0_20px_rgba(0,240,255,0.35)] transition-all transform active:scale-95 disabled:opacity-50"
            >
              {isExecuting ? (
                <>
                  <RefreshCw className="w-4 h-4 animate-spin text-slate-950" />
                  <span>Executing SOAR Playbook...</span>
                </>
              ) : (
                <>
                  <Play className="w-4 h-4 fill-current" />
                  <span>Execute Automated Response</span>
                </>
              )}
            </button>

            <button
              onClick={() => alert('Threat escalated to Tier-3 SOC Lead for manual deep-dive.')}
              className="py-2.5 px-3 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 text-xs font-mono transition-colors"
            >
              Escalate
            </button>
          </div>
        </div>
      ) : (
        <div className="space-y-3 animate-fade-in">
          <div className="p-3 rounded-lg bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-between">
            <div className="flex items-center space-x-2 text-emerald-400">
              <ShieldCheck className="w-5 h-5 shrink-0" />
              <div>
                <h5 className="text-xs font-mono font-bold uppercase tracking-wider">
                  Playbook Successfully Executed
                </h5>
                <p className="text-[11px] text-emerald-300/80 font-sans">
                  Threat contained and logged as {executedIncident.id}
                </p>
              </div>
            </div>
            <button
              onClick={() => handleViewIncident(executedIncident)}
              className="px-3 py-1.5 rounded-lg bg-emerald-500/20 hover:bg-emerald-500/30 text-emerald-300 border border-emerald-500/40 text-xs font-mono font-medium flex items-center space-x-1.5 transition-colors"
            >
              <span>View Incident</span>
              <ExternalLink className="w-3.5 h-3.5" />
            </button>
          </div>

          <div className="p-3 rounded-lg bg-slate-950/80 border border-slate-800 space-y-2 font-mono text-xs">
            {executedIncident.responseActions.map((act) => (
              <div key={act.id} className="flex items-center justify-between text-slate-300">
                <div className="flex items-center space-x-2">
                  <div className="w-4 h-4 rounded-full bg-emerald-500/20 text-emerald-400 flex items-center justify-center text-[10px] font-bold">
                    ✓
                  </div>
                  <span className="font-semibold text-emerald-300">{act.action}</span>
                </div>
                <span className="text-[10px] text-slate-500">{act.executedAt}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};
