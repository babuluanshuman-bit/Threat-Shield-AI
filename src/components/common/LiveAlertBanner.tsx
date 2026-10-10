import React from 'react';
import { useCyberGuard } from '../../context/CyberGuardContext';
import { ShieldAlert, X } from 'lucide-react';

export const LiveAlertBanner: React.FC = () => {
  const { liveAlert, dismissLiveAlert } = useCyberGuard();

  if (!liveAlert) return null;

  return (
    <div className="fixed top-16 sm:top-20 inset-x-0 z-50 flex justify-center px-3 sm:px-6 pointer-events-none">
      <div className="pointer-events-auto w-full max-w-3xl rounded-2xl bg-[#0F172A]/95 border border-rose-500/60 shadow-[0_0_30px_rgba(239,68,68,0.35)] backdrop-blur-xl p-3.5 sm:p-4 flex items-center justify-between gap-3 sm:gap-4 animate-slide-up">
        {/* Left side: Icon and Threat Info */}
        <div className="flex items-center space-x-3 min-w-0 flex-1">
          <div className="p-2 sm:p-2.5 rounded-xl bg-rose-500/20 text-rose-400 border border-rose-500/40 shrink-0">
            <ShieldAlert className="w-5 h-5 sm:w-6 sm:h-6" />
          </div>
          <div className="min-w-0 flex-1">
            <div className="flex flex-wrap items-center gap-1.5 sm:gap-2">
              <span className="px-2 py-0.5 rounded text-[9px] sm:text-[10px] font-mono font-extrabold uppercase tracking-wider bg-rose-500 text-white">
                🚨 CRITICAL ALERT
              </span>
              <span className="font-mono text-[11px] sm:text-xs font-bold text-rose-400">
                Risk Score: {liveAlert.riskScore}/100 — CRITICAL
              </span>
            </div>

            <h4 className="font-mono text-xs sm:text-sm font-bold text-white mt-1 truncate" title={liveAlert.title}>
              {liveAlert.title}
            </h4>
            <p className="text-[11px] sm:text-xs text-slate-300 font-sans mt-0.5 line-clamp-1">
              Target: <span className="font-mono text-cyan-300">{liveAlert.target}</span> • {liveAlert.summary}
            </p>
          </div>
        </div>

        {/* Right side: Dismiss Button */}
        <div className="shrink-0 flex items-center">
          <button
            onClick={dismissLiveAlert}
            className="p-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white border border-slate-700 transition-colors"
            title="Dismiss Alert"
          >
            <X className="w-4 h-4" />
          </button>
        </div>
      </div>
    </div>
  );
};
