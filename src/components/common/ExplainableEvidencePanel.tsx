import React from 'react';
import { ThreatIndicator, RiskLevel } from '../../types/cyberguard';
import { Sparkles, AlertCircle, CheckCircle2, ShieldCheck, ArrowUpRight } from 'lucide-react';
import { getRiskTheme } from '../../services/riskEngine';

interface ExplainableEvidencePanelProps {
  indicators: ThreatIndicator[];
  explanation: string;
  recommendations?: string[];
  riskScore: number;
  severity: RiskLevel;
  target?: string;
  className?: string;
}

export const ExplainableEvidencePanel: React.FC<ExplainableEvidencePanelProps> = ({
  indicators,
  explanation,
  recommendations,
  riskScore,
  severity,
  target,
  className = '',
}) => {
  const theme = getRiskTheme(severity);

  return (
    <div className={`space-y-4 ${className}`}>
      {/* Header */}
      <div className="flex items-center justify-between pb-3 border-b border-slate-800">
        <div className="flex items-center space-x-2">
          <div className="p-1.5 rounded-lg bg-cyan-500/10 border border-cyan-500/30 text-cyan-400">
            <Sparkles className="w-4 h-4" />
          </div>
          <div>
            <h4 className="text-sm font-semibold text-white tracking-wide uppercase font-mono">
              Why CYBERGUARD Flagged This
            </h4>
            <p className="text-xs text-slate-400">
              Explainable AI (XAI) feature attribution & telemetry telemetry
            </p>
          </div>
        </div>
        <div className="flex items-center space-x-2">
          <span className="text-xs text-slate-400 font-mono">Confidence:</span>
          <span className="px-2 py-0.5 rounded text-xs font-mono font-semibold bg-cyan-500/20 text-cyan-300 border border-cyan-500/30">
            98.4%
          </span>
        </div>
      </div>

      {/* Target Preview if provided */}
      {target && (
        <div className="p-2.5 rounded-lg bg-slate-950/60 border border-slate-800/80 font-mono text-xs text-slate-300 flex items-center justify-between">
          <span className="text-slate-500">Subject / Target:</span>
          <span className="text-cyan-400 font-medium truncate max-w-[320px]">{target}</span>
        </div>
      )}

      {/* Indicators Table */}
      <div className="overflow-x-auto rounded-lg border border-slate-800 bg-slate-900/60">
        <table className="w-full text-left text-xs font-mono">
          <thead>
            <tr className="border-b border-slate-800 bg-slate-950/80 text-slate-400">
              <th className="py-2.5 px-3 font-semibold">Indicator</th>
              <th className="py-2.5 px-3 font-semibold">Finding</th>
              <th className="py-2.5 px-3 text-right font-semibold">Risk Impact</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/60">
            {indicators.map((ind, idx) => {
              const isPositive = ind.impact > 0;
              return (
                <tr key={idx} className="hover:bg-slate-850/50 transition-colors">
                  <td className="py-2.5 px-3 font-medium text-slate-200 flex items-center space-x-2">
                    {isPositive ? (
                      <AlertCircle className="w-3.5 h-3.5 text-rose-400 shrink-0" />
                    ) : (
                      <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                    )}
                    <span>{ind.name}</span>
                  </td>
                  <td className="py-2.5 px-3 text-slate-300">
                    <span className="text-slate-200">{ind.finding}</span>
                    {ind.details && (
                      <p className="text-[10px] text-slate-500 mt-0.5 font-sans leading-tight">
                        {ind.details}
                      </p>
                    )}
                  </td>
                  <td className="py-2.5 px-3 text-right font-mono font-bold">
                    <span
                      className={`inline-block px-2 py-0.5 rounded text-[11px] ${
                        isPositive
                          ? 'bg-rose-500/15 text-rose-400 border border-rose-500/30'
                          : 'bg-emerald-500/15 text-emerald-400 border border-emerald-500/30'
                      }`}
                    >
                      {isPositive ? `+${ind.impact}` : ind.impact}
                    </span>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      {/* Human-Readable Explanation Box */}
      <div className={`p-4 rounded-xl border ${theme.borderClass} ${theme.bgClass} relative overflow-hidden backdrop-blur-sm`}>
        <div className="flex items-start space-x-3">
          <div className="p-1.5 rounded-md bg-slate-900/80 border border-slate-700/80 text-cyan-400 shrink-0 mt-0.5">
            <ShieldCheck className="w-4 h-4" />
          </div>
          <div className="space-y-1">
            <h5 className="text-xs font-semibold text-slate-200 font-mono flex items-center space-x-2">
              <span>CYBERGUARD AI REASONING SYNTHESIS</span>
              <span className={`text-[10px] px-1.5 py-0.5 rounded ${theme.badgeBg}`}>
                {riskScore}/100 {severity}
              </span>
            </h5>
            <p className="text-xs text-slate-300 leading-relaxed font-sans">
              {explanation}
            </p>
          </div>
        </div>
      </div>

      {/* Recommended Actions */}
      {recommendations && recommendations.length > 0 && (
        <div className="p-3 rounded-lg bg-slate-900/60 border border-slate-800">
          <h5 className="text-xs font-mono font-semibold text-slate-400 uppercase tracking-wider mb-2 flex items-center">
            <ArrowUpRight className="w-3.5 h-3.5 text-cyan-400 mr-1" /> Recommended Security Actions
          </h5>
          <ul className="space-y-1.5">
            {recommendations.map((rec, i) => (
              <li key={i} className="text-xs text-slate-300 flex items-start space-x-2">
                <span className="text-cyan-400 font-mono font-bold mt-0.5">✓</span>
                <span className="leading-snug">{rec}</span>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
};
