import React, { useState } from 'react';
import { useCyberGuard } from '../../context/CyberGuardContext';
import {
  Search,
  X,
  ShieldAlert,
  FileText,
  User,
  Globe,
  Radio,
  ExternalLink,
  Command
} from 'lucide-react';
import { SeverityBadge } from './ThreatBadge';

export const GlobalSearchModal: React.FC = () => {
  const {
    searchOpen,
    setSearchOpen,
    threats,
    incidents,
    setSelectedIncident,
    setActiveTab,
  } = useCyberGuard();

  const [query, setQuery] = useState('');

  if (!searchOpen) return null;

  const q = query.toLowerCase().trim();

  // Search across Threats
  const matchingThreats = q
    ? threats.filter(
        (t) =>
          t.title.toLowerCase().includes(q) ||
          t.target.toLowerCase().includes(q) ||
          t.category.toLowerCase().includes(q) ||
          t.id.toLowerCase().includes(q)
      )
    : threats.slice(0, 3);

  // Search across Incidents
  const matchingIncidents = q
    ? incidents.filter(
        (inc) =>
          inc.id.toLowerCase().includes(q) ||
          inc.title.toLowerCase().includes(q) ||
          inc.threatType.toLowerCase().includes(q) ||
          inc.affectedUser.toLowerCase().includes(q)
      )
    : incidents.slice(0, 3);

  const handleSelectIncident = (inc: any) => {
    setSelectedIncident(inc);
    setActiveTab('dashboard');
    setSearchOpen(false);
  };

  const handleSelectThreat = (threat: any) => {
    setActiveTab('dashboard');
    setSearchOpen(false);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center pt-16 sm:pt-20 p-2 sm:p-4 bg-slate-950/80 backdrop-blur-md animate-fade-in overflow-y-auto">
      <div className="relative w-full max-w-2xl rounded-2xl border border-cyan-500/30 bg-[#0B1120] shadow-[0_0_50px_rgba(0,0,0,0.8)] overflow-hidden">
        {/* Search Input Bar */}
        <div className="p-4 border-b border-slate-800 flex items-center space-x-3 bg-slate-950/70">
          <Search className="w-5 h-5 text-cyan-400 shrink-0" />
          <input
            type="text"
            autoFocus
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search Incident ID (INC-2026-0142), URL, Domain, IP, User, Threat Type..."
            className="flex-1 bg-transparent text-sm text-slate-100 placeholder-slate-500 font-mono focus:outline-none"
          />
          <div className="flex items-center space-x-1 px-2 py-0.5 rounded bg-slate-800 border border-slate-700 text-[10px] font-mono text-slate-400">
            <Command className="w-3 h-3" />
            <span>K</span>
          </div>
          <button
            onClick={() => setSearchOpen(false)}
            className="p-1.5 rounded-lg hover:bg-slate-800 text-slate-400 hover:text-white"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Search Results */}
        <div className="max-h-[60vh] overflow-y-auto p-4 space-y-4">
          {/* Incidents Section */}
          {matchingIncidents.length > 0 && (
            <div>
              <div className="text-[11px] font-mono font-bold uppercase tracking-wider text-slate-500 px-2 mb-2 flex items-center">
                <FileText className="w-3.5 h-3.5 mr-1.5 text-cyan-400" />
                Incidents ({matchingIncidents.length})
              </div>
              <div className="space-y-1">
                {matchingIncidents.map((inc) => (
                  <div
                    key={inc.id}
                    onClick={() => handleSelectIncident(inc)}
                    className="p-3 rounded-xl hover:bg-slate-850/80 cursor-pointer border border-transparent hover:border-slate-800 transition-all flex items-center justify-between group"
                  >
                    <div className="flex items-center space-x-3">
                      <div className="p-2 rounded-lg bg-slate-800 text-cyan-400 group-hover:bg-cyan-500/20 transition-colors">
                        <FileText className="w-4 h-4" />
                      </div>
                      <div>
                        <div className="flex items-center space-x-2">
                          <span className="font-mono text-xs font-bold text-white">
                            {inc.id}
                          </span>
                          <span className="text-xs text-slate-300 font-medium">
                            {inc.title}
                          </span>
                        </div>
                        <p className="text-[11px] text-slate-400 font-mono">
                          Target: {inc.affectedUser} • {inc.threatType}
                        </p>
                      </div>
                    </div>
                    <SeverityBadge level={inc.severity} size="sm" />
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Threats Section */}
          {matchingThreats.length > 0 && (
            <div>
              <div className="text-[11px] font-mono font-bold uppercase tracking-wider text-slate-500 px-2 mb-2 flex items-center">
                <ShieldAlert className="w-3.5 h-3.5 mr-1.5 text-rose-400" />
                Active Threats ({matchingThreats.length})
              </div>
              <div className="space-y-1">
                {matchingThreats.map((threat) => (
                  <div
                    key={threat.id}
                    onClick={() => handleSelectThreat(threat)}
                    className="p-3 rounded-xl hover:bg-slate-850/80 cursor-pointer border border-transparent hover:border-slate-800 transition-all flex items-center justify-between group"
                  >
                    <div className="flex items-center space-x-3">
                      <div className="p-2 rounded-lg bg-slate-800 text-rose-400 group-hover:bg-rose-500/20 transition-colors">
                        <ShieldAlert className="w-4 h-4" />
                      </div>
                      <div>
                        <div className="flex items-center space-x-2">
                          <span className="font-mono text-xs font-bold text-slate-200">
                            {threat.title}
                          </span>
                        </div>
                        <p className="text-[11px] text-slate-400 font-mono truncate max-w-md">
                          {threat.target} • {threat.category}
                        </p>
                      </div>
                    </div>
                    <span className="font-mono text-xs font-bold text-rose-400">
                      {threat.riskScore}/100
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {matchingIncidents.length === 0 && matchingThreats.length === 0 && (
            <div className="py-10 text-center text-slate-500 font-mono text-xs">
              No matching security records found for "{query}"
            </div>
          )}
        </div>

        {/* Footer shortcuts */}
        <div className="p-2.5 px-4 bg-slate-950/80 border-t border-slate-800 flex items-center justify-between text-[11px] font-mono text-slate-500">
          <span>Navigate with arrows, Enter to select</span>
          <span>ESC to close</span>
        </div>
      </div>
    </div>
  );
};
