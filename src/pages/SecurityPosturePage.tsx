import React from 'react';
import { useCyberGuard } from '../context/CyberGuardContext';
import { RiskGauge } from '../components/common/RiskGauge';
import {
  Gauge,
  ShieldCheck,
  CheckCircle2,
  AlertTriangle,
  ArrowUpRight,
  Sparkles,
  Zap
} from 'lucide-react';
import confetti from 'canvas-confetti';

export const SecurityPosturePage: React.FC = () => {
  const { posture, remediatePostureItem } = useCyberGuard();

  const handleRemediate = (id: string) => {
    remediatePostureItem(id);
    try {
      confetti({
        particleCount: 40,
        spread: 50,
        origin: { y: 0.7 },
        colors: ['#10B981', '#00F0FF'],
      });
    } catch (e) {
      // ignore
    }
  };

  return (
    <div className="space-y-6 pb-12 animate-fade-in max-w-6xl mx-auto">
      {/* Header */}
      <div className="p-4 rounded-2xl bg-[#0B1120] border border-slate-800">
        <div className="flex items-center space-x-3">
          <div className="p-2 rounded-xl bg-emerald-500/10 border border-emerald-500/30 text-emerald-400">
            <Gauge className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center space-x-2">
              <h1 className="text-xl font-mono font-bold text-white tracking-wide">
                ENTERPRISE CYBERSECURITY POSTURE SCORECARD
              </h1>
              <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase tracking-wider bg-emerald-500/20 text-emerald-300 border border-emerald-500/30">
                SCORE 82/100 (GRADE A-)
              </span>
            </div>
            <p className="text-xs text-slate-400 font-sans mt-0.5">
              Continuous assessment across Identity, Email Gateway, Boundary Firewalls, Behavioral Baselines, and SOAR Response Readiness.
            </p>
          </div>
        </div>
      </div>

      {/* Main Score & Category Breakdown Cards */}
      <div className="grid grid-cols-1 md:grid-cols-12 gap-6">
        {/* Left: Overall Gauge Card */}
        <div className="md:col-span-5 p-6 rounded-2xl bg-[#070C18] border border-slate-800 shadow-cyber-card flex flex-col items-center justify-center text-center">
          <span className="text-[11px] font-mono uppercase tracking-widest text-slate-400 mb-2">
            CyberGuard Security Score
          </span>
          <RiskGauge score={posture.overallScore} size="lg" subtext="Organization-Wide Resiliency Index" />

          <div className="mt-6 p-3 rounded-xl bg-slate-950 border border-slate-850 text-xs font-mono text-slate-300 space-y-1 w-full">
            <div className="flex justify-between">
              <span className="text-slate-500">Benchmark:</span>
              <span className="text-cyan-400 font-bold">Top 8% in Industry</span>
            </div>
            <div className="flex justify-between">
              <span className="text-slate-500">Target Goal:</span>
              <span className="text-emerald-400 font-bold">95/100 (Grade A+)</span>
            </div>
          </div>
        </div>

        {/* Right: Breakdown Progress Bars */}
        <div className="md:col-span-7 p-6 rounded-2xl bg-[#070C18] border border-slate-800 shadow-cyber-card flex flex-col justify-between space-y-4">
          <div className="pb-3 border-b border-slate-800 flex items-center justify-between">
            <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-white">
              Category Resiliency Breakdown
            </h3>
            <span className="text-xs font-mono text-cyan-400 font-bold">6 Dimensions Evaluated</span>
          </div>

          <div className="space-y-3 font-mono text-xs">
            {Object.entries(posture.categories).map(([cat, score]) => (
              <div key={cat} className="space-y-1">
                <div className="flex items-center justify-between">
                  <span className="text-slate-300">{cat}</span>
                  <span className={`font-bold ${score >= 80 ? 'text-emerald-400' : score >= 70 ? 'text-amber-400' : 'text-rose-400'}`}>
                    {score}/100
                  </span>
                </div>
                <div className="w-full h-1.5 bg-slate-900 rounded-full overflow-hidden">
                  <div
                    className={`h-full transition-all duration-500 ${
                      score >= 80 ? 'bg-gradient-to-r from-emerald-500 to-teal-400' : score >= 70 ? 'bg-amber-400' : 'bg-rose-500'
                    }`}
                    style={{ width: `${score}%` }}
                  />
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Actionable Recommendations List */}
      <div className="p-6 rounded-2xl bg-[#070C18] border border-slate-800 shadow-cyber-card space-y-4">
        <div className="flex items-center justify-between pb-3 border-b border-slate-800">
          <div className="flex items-center space-x-2">
            <Sparkles className="w-4 h-4 text-cyan-400" />
            <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-white">
              Actionable AI Posture Remediations
            </h3>
          </div>
          <span className="text-[10px] font-mono text-cyan-400">One-Click Remediation Active</span>
        </div>

        <div className="space-y-2.5 font-mono text-xs">
          {posture.recommendations.map((rec) => (
            <div
              key={rec.id}
              className={`p-3.5 rounded-xl border flex flex-col sm:flex-row sm:items-center justify-between gap-3 transition-all ${
                rec.remediated
                  ? 'bg-emerald-950/20 border-emerald-500/30 text-emerald-300'
                  : 'bg-slate-900/60 border-slate-800 hover:border-slate-750'
              }`}
            >
              <div className="flex items-start space-x-3">
                <div
                  className={`w-5 h-5 rounded-full flex items-center justify-center text-[10px] shrink-0 mt-0.5 ${
                    rec.remediated ? 'bg-emerald-500 text-slate-950 font-bold' : 'bg-slate-800 text-cyan-400'
                  }`}
                >
                  {rec.remediated ? '✓' : '•'}
                </div>
                <div>
                  <span className={`font-bold block ${rec.remediated ? 'line-through text-slate-400' : 'text-slate-100'}`}>
                    {rec.title}
                  </span>
                  <span className="text-[10px] text-slate-500 font-sans block mt-0.5">
                    Category: {rec.category} • Impact: <strong className="text-cyan-400">{rec.impact}</strong>
                  </span>
                </div>
              </div>

              <div>
                {rec.remediated ? (
                  <span className="px-3 py-1 rounded-lg bg-emerald-500/20 text-emerald-300 border border-emerald-500/40 text-[10px] font-bold uppercase">
                    Remediated
                  </span>
                ) : (
                  <button
                    onClick={() => handleRemediate(rec.id)}
                    className="px-3.5 py-1.5 rounded-lg bg-cyan-500/20 hover:bg-cyan-500/30 text-cyan-300 border border-cyan-500/40 text-[10px] font-bold uppercase transition-colors shrink-0"
                  >
                    Execute Remediation
                  </button>
                )}
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
