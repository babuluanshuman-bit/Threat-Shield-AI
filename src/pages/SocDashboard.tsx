import React, { useState } from 'react';
import { useCyberGuard } from '../context/CyberGuardContext';
import { GlobalThreatMap } from '../components/dashboard/GlobalThreatMap';
import { SeverityBadge, ThreatBadge } from '../components/common/ThreatBadge';
import { HIGH_RISK_USERS } from '../data/mockCyberData';
import {
  ShieldAlert,
  ShieldCheck,
  Zap,
  Activity,
  UserCheck,
  TrendingUp,
  AlertTriangle,
  Play,
  Pause,
  ExternalLink,
  Ban,
  Radio,
  FileText
} from 'lucide-react';
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  BarChart,
  Bar,
  Cell,
  LabelList
} from 'recharts';

export const SocDashboard: React.FC = () => {
  const {
    metrics,
    threats,
    incidents,
    auditLogs,
    setSelectedIncident,
    setActiveTab,
    triggerLiveAttackDemo,
    executeSOAR,
  } = useCyberGuard();

  const [isFeedPaused, setIsFeedPaused] = useState(false);

  // Trend data for Recharts
  const trendData = [
    { time: '06:00', threats: 120, blocked: 98, critical: 4 },
    { time: '08:00', threats: 240, blocked: 210, critical: 8 },
    { time: '10:00', threats: 480, blocked: 420, critical: 14 },
    { time: '12:00', threats: 620, blocked: 560, critical: 19 },
    { time: '14:00', threats: 890, blocked: 780, critical: 22 },
    { time: '16:00', threats: 1140, blocked: 890, critical: 25 },
    { time: 'Now', threats: metrics.threatsDetected, blocked: metrics.blockedThreats, critical: metrics.criticalThreats },
  ];

  const categoryDistribution = [
    { category: 'Phishing', count: 438, color: '#EF4444' },
    { category: 'Impersonation', count: 126, color: '#A855F7' },
    { category: 'ATO & Auth', count: 215, color: '#F97316' },
    { category: 'Network C2', count: 184, color: '#00F0FF' },
    { category: 'Deepfake', count: 92, color: '#3B82F6' },
    { category: 'Malicious Files', count: 229, color: '#E11D48' },
  ];

  const handleOpenIncident = (inc: any) => {
    setSelectedIncident(inc);
  };

  return (
    <div className="space-y-6 pb-12 animate-fade-in">
      {/* Top Header & Simulation Trigger Bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 p-4 rounded-2xl bg-[#0B1120] border border-slate-800">
        <div>
          <div className="flex flex-wrap items-center gap-2">
            <h1 className="text-lg sm:text-xl font-mono font-bold text-white tracking-wide">
              CYBERGUARD COMMAND CENTER (SOC)
            </h1>
            <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase tracking-wider bg-emerald-500/20 text-emerald-300 border border-emerald-500/30">
              AUTONOMOUS DEFENSE ACTIVE
            </span>
          </div>
          <p className="text-xs text-slate-400 font-sans mt-0.5">
            Real-time multi-modal cyber threat detection, explainable risk scoring, and automated SOAR containment.
          </p>
        </div>

        <button
          onClick={() => triggerLiveAttackDemo('scenario-phishing')}
          className="w-full sm:w-auto shrink-0 flex items-center justify-center space-x-2 py-2.5 px-5 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-slate-950 font-mono font-bold text-xs uppercase tracking-wider shadow-[0_0_20px_rgba(0,240,255,0.4)] transition-all transform active:scale-95"
        >
          <Zap className="w-4 h-4 fill-slate-950 text-slate-950" />
          <span>RUN LIVE ATTACK SIMULATION</span>
        </button>
      </div>

      {/* Top 7 Stat Cards */}
      <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-7 gap-3 font-mono">
        <div className="p-3.5 rounded-xl bg-slate-900/80 border border-slate-800">
          <span className="text-[10px] text-slate-400 uppercase tracking-wider block">Threats Detected</span>
          <span className="text-xl font-extrabold text-white mt-1 block">{metrics.threatsDetected}</span>
          <span className="text-[9px] text-cyan-400 font-semibold">↑ +14 today</span>
        </div>

        <div className="p-3.5 rounded-xl bg-slate-900/80 border border-rose-500/30 shadow-[0_0_15px_rgba(239,68,68,0.15)]">
          <span className="text-[10px] text-rose-400 uppercase tracking-wider block">Critical</span>
          <span className="text-xl font-extrabold text-rose-400 mt-1 block">{metrics.criticalThreats}</span>
          <span className="text-[9px] text-rose-300 font-semibold">Immediate Action</span>
        </div>

        <div className="p-3.5 rounded-xl bg-slate-900/80 border border-slate-800">
          <span className="text-[10px] text-slate-400 uppercase tracking-wider block">Phishing</span>
          <span className="text-xl font-extrabold text-cyan-400 mt-1 block">{metrics.phishingThreats}</span>
          <span className="text-[9px] text-slate-500 font-semibold">URLs & Emails</span>
        </div>

        <div className="p-3.5 rounded-xl bg-slate-900/80 border border-slate-800">
          <span className="text-[10px] text-slate-400 uppercase tracking-wider block">Impersonation</span>
          <span className="text-xl font-extrabold text-purple-400 mt-1 block">{metrics.impersonationThreats}</span>
          <span className="text-[9px] text-slate-500 font-semibold">Look-Alikes</span>
        </div>

        <div className="p-3.5 rounded-xl bg-slate-900/80 border border-emerald-500/30">
          <span className="text-[10px] text-emerald-400 uppercase tracking-wider block">Blocked SOAR</span>
          <span className="text-xl font-extrabold text-emerald-400 mt-1 block">{metrics.blockedThreats}</span>
          <span className="text-[9px] text-emerald-300 font-semibold">99.2% Mitigated</span>
        </div>

        <div className="p-3.5 rounded-xl bg-slate-900/80 border border-slate-800">
          <span className="text-[10px] text-slate-400 uppercase tracking-wider block">Active Incidents</span>
          <span className="text-xl font-extrabold text-amber-400 mt-1 block">{metrics.activeIncidents}</span>
          <span className="text-[9px] text-amber-300 font-semibold">In Triage</span>
        </div>

        <div className="p-3.5 rounded-xl bg-slate-900/80 border border-slate-800">
          <span className="text-[10px] text-slate-400 uppercase tracking-wider block">Protected Nodes</span>
          <span className="text-xl font-extrabold text-slate-200 mt-1 block">{metrics.protectedUsers.toLocaleString()}</span>
          <span className="text-[9px] text-slate-500 font-semibold">Endpoints</span>
        </div>
      </div>


      {/* Row 2: Global Attack Map + Category Distribution */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        <div className="lg:col-span-8">
          <GlobalThreatMap />
        </div>

        {/* Category Breakdown & Risk Gauge */}
        <div className="lg:col-span-4 rounded-2xl border border-slate-800 bg-[#070C18] p-5 flex flex-col justify-between shadow-cyber-card">
          <div className="pb-3 border-b border-slate-800 flex items-center justify-between">
            <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-white">
              Threat Distribution by Modality
            </h3>
            <span className="text-[10px] font-mono text-cyan-400">Total: 1,284</span>
          </div>

          <div className="flex-1 min-h-[380px] sm:min-h-[420px] w-full my-3">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart
                data={categoryDistribution}
                layout="vertical"
                margin={{ top: 10, right: 35, left: 15, bottom: 10 }}
              >
                <XAxis type="number" hide />
                <YAxis
                  dataKey="category"
                  type="category"
                  width={110}
                  tick={{ fill: '#cbd5e1', fontSize: 11, fontFamily: 'JetBrains Mono', fontWeight: 600 }}
                  axisLine={{ stroke: '#334155' }}
                  tickLine={false}
                />
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#0b1120',
                    borderColor: '#1e293b',
                    borderRadius: '8px',
                    fontSize: '11px',
                    fontFamily: 'JetBrains Mono',
                  }}
                  itemStyle={{ color: '#00f0ff' }}
                />
                <Bar dataKey="count" radius={[0, 6, 6, 0]} barSize={22}>
                  {categoryDistribution.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} />
                  ))}
                  <LabelList
                    dataKey="count"
                    position="right"
                    fill="#94a3b8"
                    fontSize={11}
                    fontFamily="JetBrains Mono"
                  />
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>

          {/* Autonomous Response Consensus Footer */}
          <div className="pt-3 border-t border-slate-800 flex items-center justify-between">
            <div>
              <span className="text-[10px] font-mono text-slate-400 block uppercase">Multi-Engine Consensus</span>
              <span className="text-xs font-mono font-bold text-emerald-400">99.4% Mitigation Fidelity</span>
            </div>
            <div className="flex items-center space-x-1.5 text-[10px] font-mono text-cyan-400 bg-cyan-500/10 px-2 py-1 rounded-lg border border-cyan-500/30">
              <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-pulse" />
              <span>SOAR Armed</span>
            </div>
          </div>
        </div>
      </div>

      {/* Row 3: Threat Trend Chart (AreaChart) */}
      <div className="rounded-2xl border border-slate-800 bg-[#070C18] p-5 shadow-cyber-card">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-3 border-b border-slate-800 mb-4">
          <div className="flex items-center space-x-2">
            <TrendingUp className="w-4 h-4 text-cyan-400" />
            <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-white">
              24-Hour Threat Ingestion & Mitigation Telemetry
            </h3>
          </div>
          <div className="flex flex-wrap items-center gap-2 sm:gap-4 text-[10px] sm:text-[11px] font-mono">
            <span className="flex items-center space-x-1.5 text-cyan-400">
              <span className="w-2 h-2 rounded-full bg-cyan-400" />
              <span>Total Threats</span>
            </span>
            <span className="flex items-center space-x-1.5 text-emerald-400">
              <span className="w-2 h-2 rounded-full bg-emerald-400" />
              <span>SOAR Blocked</span>
            </span>
            <span className="flex items-center space-x-1.5 text-rose-400">
              <span className="w-2 h-2 rounded-full bg-rose-400" />
              <span>Critical Alerts</span>
            </span>
          </div>
        </div>

        <div className="h-[220px] w-full">
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={trendData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
              <defs>
                <linearGradient id="threatGrad" x1="0%" y1="0%" x2="0%" y2="100%">
                  <stop offset="0%" stopColor="#00F0FF" stopOpacity={0.3} />
                  <stop offset="100%" stopColor="#00F0FF" stopOpacity={0.0} />
                </linearGradient>
                <linearGradient id="blockedGrad" x1="0%" y1="0%" x2="0%" y2="100%">
                  <stop offset="0%" stopColor="#10B981" stopOpacity={0.3} />
                  <stop offset="100%" stopColor="#10B981" stopOpacity={0.0} />
                </linearGradient>
              </defs>
              <XAxis dataKey="time" stroke="#475569" tick={{ fill: '#94a3b8', fontSize: 10, fontFamily: 'JetBrains Mono' }} />
              <YAxis stroke="#475569" tick={{ fill: '#94a3b8', fontSize: 10, fontFamily: 'JetBrains Mono' }} />
              <Tooltip
                contentStyle={{ backgroundColor: '#0b1120', borderColor: '#1e293b', borderRadius: '8px', fontSize: '11px', fontFamily: 'JetBrains Mono' }}
              />
              <Area type="monotone" dataKey="threats" stroke="#00F0FF" strokeWidth={2} fill="url(#threatGrad)" />
              <Area type="monotone" dataKey="blocked" stroke="#10B981" strokeWidth={2} fill="url(#blockedGrad)" />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Row 4: Live Threat Feed + Active Incidents + High Risk Users */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left Column: Live Threat Feed */}
        <div className="lg:col-span-6 rounded-2xl border border-slate-800 bg-[#070C18] p-5 shadow-cyber-card flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between pb-3 border-b border-slate-800 mb-3">
              <div className="flex items-center space-x-2">
                <Radio className="w-4 h-4 text-rose-400 animate-pulse" />
                <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-white">
                  Live Multi-Modal Threat Stream
                </h3>
              </div>
              <div className="flex items-center space-x-2">
                <button
                  onClick={() => setIsFeedPaused(!isFeedPaused)}
                  className="px-2 py-0.5 rounded text-[10px] font-mono bg-slate-800 hover:bg-slate-700 text-slate-300 flex items-center space-x-1"
                >
                  {isFeedPaused ? <Play className="w-2.5 h-2.5" /> : <Pause className="w-2.5 h-2.5" />}
                  <span>{isFeedPaused ? 'Resume' : 'Pause'}</span>
                </button>
              </div>
            </div>

            <div className="space-y-2.5 max-h-[360px] overflow-y-auto pr-1">
              {threats.map((threat) => (
                <div
                  key={threat.id}
                  className="p-3 rounded-xl bg-slate-900/70 border border-slate-800/80 hover:border-slate-750 transition-all space-y-2"
                >
                  <div className="flex items-center justify-between">
                    <div className="flex items-center space-x-2">
                      <ThreatBadge category={threat.category} size="sm" />
                      <span className="text-[10px] font-mono text-slate-500">{threat.timestamp}</span>
                    </div>
                    <SeverityBadge level={threat.severity} size="sm" />
                  </div>

                  <div>
                    <h5 className="font-mono text-xs font-bold text-slate-200">
                      {threat.title}
                    </h5>
                    <p className="text-xs text-slate-400 font-sans line-clamp-1 mt-0.5">
                      {threat.summary}
                    </p>
                  </div>

                  <div className="flex items-center justify-between pt-1 border-t border-slate-850 text-xs font-mono">
                    <span className="text-slate-500 text-[11px] truncate max-w-[200px]">
                      Target: {threat.target}
                    </span>

                    {threat.status !== 'CONTAINED' && threat.status !== 'BLOCKED' ? (
                      <button
                        onClick={() => executeSOAR(threat)}
                        className="px-2 py-0.5 rounded bg-cyan-500/20 hover:bg-cyan-500/30 text-cyan-300 border border-cyan-500/40 text-[10px] font-bold uppercase transition-colors"
                      >
                        Execute SOAR
                      </button>
                    ) : (
                      <span className="text-emerald-400 text-[10px] font-bold">
                        ✓ {threat.status}
                      </span>
                    )}
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Right Column: Active Incidents & High Risk Users */}
        <div className="lg:col-span-6 space-y-6">
          {/* Active Incidents Card */}
          <div className="rounded-2xl border border-slate-800 bg-[#070C18] p-5 shadow-cyber-card">
            <div className="flex items-center justify-between pb-3 border-b border-slate-800 mb-3">
              <div className="flex items-center space-x-2">
                <FileText className="w-4 h-4 text-cyan-400" />
                <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-white">
                  Active SOC Incidents ({incidents.length})
                </h3>
              </div>
              <span className="text-[10px] font-mono text-cyan-400 bg-cyan-500/10 px-2 py-0.5 rounded border border-cyan-500/20">
                LIVE QUEUE
              </span>
            </div>

            <div className="space-y-2">
              {incidents.slice(0, 3).map((inc) => (
                <div
                  key={inc.id}
                  onClick={() => handleOpenIncident(inc)}
                  className="p-3 rounded-xl bg-slate-900/60 border border-slate-800 hover:border-cyan-500/30 cursor-pointer transition-all flex items-center justify-between"
                >
                  <div>
                    <div className="flex items-center space-x-2">
                      <span className="font-mono text-xs font-bold text-cyan-400">{inc.id}</span>
                      <span className="font-mono text-xs font-bold text-white">{inc.threatType}</span>
                    </div>
                    <p className="text-[11px] text-slate-400 font-sans mt-0.5">
                      Target: {inc.affectedUser} • {inc.timeline.length} Events Logged
                    </p>
                  </div>
                  <div className="text-right">
                    <SeverityBadge level={inc.severity} size="sm" />
                    <span className="text-[10px] font-mono text-slate-500 block mt-1">{inc.status}</span>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* High-Risk Users Card */}
          <div className="rounded-2xl border border-slate-800 bg-[#070C18] p-5 shadow-cyber-card">
            <div className="flex items-center justify-between pb-3 border-b border-slate-800 mb-3">
              <div className="flex items-center space-x-2">
                <UserCheck className="w-4 h-4 text-amber-400" />
                <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-white">
                  High-Risk User Telemetry
                </h3>
              </div>
              <span className="text-[10px] font-mono text-slate-400">UEBA Anomaly Watch</span>
            </div>

            <div className="space-y-2">
              {HIGH_RISK_USERS.slice(0, 3).map((u) => (
                <div
                  key={u.id}
                  className="p-2.5 rounded-xl bg-slate-900/60 border border-slate-800 flex items-center justify-between font-mono text-xs"
                >
                  <div>
                    <span className="font-bold text-slate-200">{u.name}</span>
                    <span className="text-slate-500 text-[11px] ml-1.5">({u.role})</span>
                    <p className="text-[10px] text-amber-400 font-sans mt-0.5">{u.reason}</p>
                  </div>
                  <div className="text-right">
                    <span className="font-bold text-rose-400">{u.riskScore}/100</span>
                    <span className="text-[10px] text-slate-400 block">{u.status}</span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
