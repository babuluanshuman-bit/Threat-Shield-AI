import React, { useState } from 'react';
import { INITIAL_CAMPAIGNS, INITIAL_IOCS } from '../services/threatIntelligence';
import { SeverityBadge } from '../components/common/ThreatBadge';
import {
  Radio,
  ShieldAlert,
  Search,
  ExternalLink,
  Layers,
  Filter,
  BarChart3,
  TrendingUp,
  Globe,
  Database
} from 'lucide-react';
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell
} from 'recharts';

export const ThreatIntelligencePage: React.FC = () => {
  const [filterType, setFilterType] = useState('ALL');
  const [searchTerm, setSearchTerm] = useState('');

  const targetedBrandsData = [
    { brand: 'Microsoft 365', campaigns: 42, color: '#A855F7' },
    { brand: 'State Bank of India', campaigns: 38, color: '#00F0FF' },
    { brand: 'PayPal Services', campaigns: 31, color: '#3B82F6' },
    { brand: 'Google Workspace', campaigns: 24, color: '#10B981' },
    { brand: 'Apple iCloud', campaigns: 18, color: '#F97316' },
  ];

  const severityPieData = [
    { name: 'Critical (81-100)', value: 27, color: '#EF4444' },
    { name: 'High (61-80)', value: 48, color: '#F97316' },
    { name: 'Medium (41-60)', value: 35, color: '#F59E0B' },
    { name: 'Low/Safe (0-40)', value: 94, color: '#10B981' },
  ];

  const filteredIoCs = INITIAL_IOCS.filter((ioc) => {
    const matchesType = filterType === 'ALL' || ioc.type === filterType;
    const matchesSearch =
      ioc.value.toLowerCase().includes(searchTerm.toLowerCase()) ||
      ioc.threatType.toLowerCase().includes(searchTerm.toLowerCase());
    return matchesType && matchesSearch;
  });

  return (
    <div className="space-y-6 pb-12 animate-fade-in max-w-6xl mx-auto">
      {/* Header */}
      <div className="p-4 rounded-2xl bg-[#0B1120] border border-slate-800">
        <div className="flex items-center space-x-3">
          <div className="p-2 rounded-xl bg-cyan-500/10 border border-cyan-500/30 text-cyan-400">
            <Radio className="w-5 h-5 animate-pulse" />
          </div>
          <div>
            <div className="flex items-center space-x-2">
              <h1 className="text-xl font-mono font-bold text-white tracking-wide">
                GLOBAL THREAT INTELLIGENCE & IOC TELEMETRY
              </h1>
              <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase tracking-wider bg-cyan-500/20 text-cyan-300 border border-cyan-500/30">
                LIVE STIX/TAXII SYNC
              </span>
            </div>
            <p className="text-xs text-slate-400 font-sans mt-0.5">
              Curated Indicators of Compromise (IoCs), active APT campaign clusters, targeted enterprise brand telemetry, and reputation feeds.
            </p>
          </div>
        </div>
      </div>

      {/* Row 1: Charts (Top Targeted Brands & Severity Distribution) */}
      <div className="grid grid-cols-1 md:grid-cols-12 gap-6">
        {/* Top Targeted Brands */}
        <div className="md:col-span-7 p-5 rounded-2xl bg-[#070C18] border border-slate-800 shadow-cyber-card flex flex-col justify-between">
          <div className="pb-3 border-b border-slate-800 flex items-center justify-between mb-2">
            <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-white flex items-center">
              <BarChart3 className="w-4 h-4 text-cyan-400 mr-2" />
              Top Targeted Enterprise Brands (Active Campaigns)
            </h3>
          </div>

          <div className="h-[200px] w-full">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={targetedBrandsData} layout="vertical" margin={{ top: 5, right: 20, left: 35, bottom: 5 }}>
                <XAxis type="number" tick={{ fill: '#94a3b8', fontSize: 10, fontFamily: 'JetBrains Mono' }} />
                <YAxis dataKey="brand" type="category" width={110} tick={{ fill: '#94a3b8', fontSize: 10, fontFamily: 'JetBrains Mono' }} />
                <Tooltip
                  contentStyle={{ backgroundColor: '#0b1120', borderColor: '#1e293b', borderRadius: '8px', fontSize: '11px', fontFamily: 'JetBrains Mono' }}
                />
                <Bar dataKey="campaigns" radius={[0, 4, 4, 0]}>
                  {targetedBrandsData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Severity Distribution Pie */}
        <div className="md:col-span-5 p-5 rounded-2xl bg-[#070C18] border border-slate-800 shadow-cyber-card flex flex-col justify-between">
          <div className="pb-3 border-b border-slate-800 flex items-center justify-between mb-2">
            <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-white">
              Threat Severity Distribution
            </h3>
          </div>

          <div className="h-[200px] w-full flex items-center justify-center">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={severityPieData}
                  cx="50%"
                  cy="50%"
                  innerRadius={50}
                  outerRadius={75}
                  paddingAngle={4}
                  dataKey="value"
                >
                  {severityPieData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} />
                  ))}
                </Pie>
                <Tooltip
                  contentStyle={{ backgroundColor: '#0b1120', borderColor: '#1e293b', borderRadius: '8px', fontSize: '11px', fontFamily: 'JetBrains Mono' }}
                />
              </PieChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* Row 2: Active Threat Campaigns */}
      <div className="p-6 rounded-2xl bg-[#070C18] border border-slate-800 shadow-cyber-card space-y-4">
        <div className="flex items-center justify-between pb-3 border-b border-slate-800">
          <div className="flex items-center space-x-2">
            <ShieldAlert className="w-4 h-4 text-rose-400" />
            <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-white">
              Active APT & Threat Actor Campaigns
            </h3>
          </div>
          <span className="text-[10px] font-mono text-cyan-400">3 Campaigns Tracked</span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {INITIAL_CAMPAIGNS.map((camp) => (
            <div
              key={camp.id}
              className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 space-y-2 font-mono text-xs flex flex-col justify-between"
            >
              <div>
                <div className="flex items-center justify-between mb-1.5">
                  <span className="text-cyan-400 font-bold">{camp.id}</span>
                  <SeverityBadge level={camp.severity as any} size="sm" />
                </div>
                <h4 className="text-white font-bold text-xs">{camp.name}</h4>
                <p className="text-[11px] text-slate-400 font-sans mt-1">
                  Actor: <strong className="text-slate-200">{camp.threatActor}</strong>
                </p>
                <p className="text-[11px] text-slate-400 font-sans">
                  Target: {camp.targetedSector}
                </p>
                <p className="text-[10px] text-slate-500 font-sans mt-2 leading-relaxed">
                  {camp.description}
                </p>
              </div>

              <div className="pt-2 border-t border-slate-850 flex items-center justify-between text-[10px] text-slate-400 mt-3">
                <span>Active IoCs: <strong className="text-rose-400">{camp.activeIoCs}</strong></span>
                <span>Detected: {camp.firstDetected}</span>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Row 3: Live Indicators of Compromise (IoCs) Database */}
      <div className="p-6 rounded-2xl bg-[#070C18] border border-slate-800 shadow-cyber-card space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-slate-800">
          <div className="flex items-center space-x-2">
            <Database className="w-4 h-4 text-cyan-400" />
            <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-white">
              Verified IoC Database (Live Blacklist Feeds)
            </h3>
          </div>

          <div className="flex flex-wrap items-center gap-2 font-mono text-xs">
            <div className="relative">
              <Search className="w-3.5 h-3.5 absolute left-2.5 top-1/2 -translate-y-1/2 text-slate-500" />
              <input
                type="text"
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                placeholder="Search IoC value..."
                className="pl-8 pr-3 py-1 rounded-lg bg-slate-950 border border-slate-800 text-xs text-white placeholder-slate-500 focus:outline-none"
              />
            </div>

            <div className="flex items-center space-x-1">
              {['ALL', 'URL', 'Domain', 'IP', 'Hash'].map((type) => (
                <button
                  key={type}
                  onClick={() => setFilterType(type)}
                  className={`px-2 py-1 rounded text-[11px] border transition-all ${
                    filterType === type
                      ? 'bg-cyan-500/20 text-cyan-300 border-cyan-500/40 font-bold'
                      : 'bg-slate-900 text-slate-400 border-slate-800'
                  }`}
                >
                  {type}
                </button>
              ))}
            </div>
          </div>
        </div>

        <div className="overflow-x-auto rounded-xl border border-slate-850">
          <table className="w-full text-left font-mono text-xs">
            <thead>
              <tr className="bg-slate-950 text-slate-400 border-b border-slate-800">
                <th className="py-2.5 px-4">IoC Identifier</th>
                <th className="py-2.5 px-4">Type</th>
                <th className="py-2.5 px-4">Observed Value</th>
                <th className="py-2.5 px-4">Threat Classification</th>
                <th className="py-2.5 px-4">Telemetry Source</th>
                <th className="py-2.5 px-4">Severity</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-850 bg-slate-900/40">
              {filteredIoCs.map((ioc) => (
                <tr key={ioc.id} className="hover:bg-slate-850/60 transition-colors">
                  <td className="py-2.5 px-4 text-cyan-400 font-bold">{ioc.id}</td>
                  <td className="py-2.5 px-4">
                    <span className="px-2 py-0.5 rounded bg-slate-800 border border-slate-700 text-[10px] text-slate-300">
                      {ioc.type}
                    </span>
                  </td>
                  <td className="py-2.5 px-4 text-white font-semibold truncate max-w-xs">{ioc.value}</td>
                  <td className="py-2.5 px-4 text-slate-300">{ioc.threatType}</td>
                  <td className="py-2.5 px-4 text-slate-400 text-[11px]">{ioc.reportedBy}</td>
                  <td className="py-2.5 px-4">
                    <SeverityBadge level={ioc.severity} size="sm" />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
