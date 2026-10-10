import React, { useState, useEffect } from 'react';
import { useCyberGuard } from '../context/CyberGuardContext';
import { SeverityBadge, ThreatBadge } from '../components/common/ThreatBadge';
import {
  FileText,
  Clock,
  ShieldCheck,
  CheckCircle2,
  RotateCcw,
  MessageSquare,
} from 'lucide-react';

export const IncidentCenterPage: React.FC = () => {
  const {
    incidents,
    selectedIncident,
    setSelectedIncident,
    updateIncidentStatus,
    setCopilotOpen,
  } = useCyberGuard();

  const [selectedIncidentId, setSelectedIncidentId] = useState<string>(
    selectedIncident?.id || incidents[0]?.id || ''
  );

  useEffect(() => {
    if (selectedIncident?.id) {
      setSelectedIncidentId(selectedIncident.id);
    }
  }, [selectedIncident?.id]);

  const [filterStatus, setFilterStatus] = useState<string>('ALL');

  const filteredIncidents = filterStatus === 'ALL'
    ? incidents
    : incidents.filter((i) => i.status === filterStatus);

  // Always resolve active incident from the live incidents state
  const active = incidents.find((i) => i.id === selectedIncidentId) || filteredIncidents[0] || incidents[0];

  return (
    <div className="space-y-6 pb-12 animate-fade-in max-w-6xl mx-auto">
      {/* Header */}
      <div className="p-4 rounded-2xl bg-[#0B1120] border border-slate-800">
        <div className="flex items-center space-x-3">
          <div className="p-2 rounded-xl bg-cyan-500/10 border border-cyan-500/30 text-cyan-400">
            <FileText className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center space-x-2">
              <h1 className="text-xl font-mono font-bold text-white tracking-wide">
                INCIDENT RESPONSE & LIFECYCLE MANAGEMENT CENTER
              </h1>
            </div>
            <p className="text-xs text-slate-400 font-sans mt-0.5">
              Comprehensive SOC ticketing system tracking forensic telemetry, multi-modal evidence chains, and automated SOAR remediation statuses.
            </p>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left Column: Incidents Table (5 cols) */}
        <div className="lg:col-span-5 space-y-4">
          <div className="p-4 rounded-2xl bg-[#070C18] border border-slate-800 shadow-cyber-card space-y-3">
            <div className="flex items-center justify-between pb-2 border-b border-slate-800">
              <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-white">
                Active SOC Tickets ({incidents.length})
              </h3>
              <div className="flex items-center space-x-1 font-mono text-[10px] overflow-x-auto">
                {['ALL', 'DETECTED', 'INVESTIGATING', 'CONTAINED', 'RESOLVED'].map((st) => (
                  <button
                    key={st}
                    onClick={() => setFilterStatus(st)}
                    className={`px-2 py-0.5 rounded border transition-all ${
                      filterStatus === st
                        ? 'bg-cyan-500/20 text-cyan-300 border-cyan-500/40 font-bold'
                        : 'bg-slate-900 text-slate-400 border-slate-800 hover:text-slate-200'
                    }`}
                  >
                    {st}
                  </button>
                ))}
              </div>
            </div>

            <div className="space-y-2 max-h-[580px] overflow-y-auto pr-1">
              {filteredIncidents.length === 0 ? (
                <div className="p-6 text-center text-slate-500 text-xs font-mono">
                  No incidents matching filter "{filterStatus}".
                </div>
              ) : (
                filteredIncidents.map((inc) => {
                  const isSelected = active?.id === inc.id;

                  return (
                    <div
                      key={inc.id}
                      onClick={() => {
                        setSelectedIncidentId(inc.id);
                        setSelectedIncident(inc);
                      }}
                      className={`p-3 rounded-xl border cursor-pointer transition-all ${
                        isSelected
                          ? 'bg-cyan-500/15 border-cyan-500/50 shadow-[0_0_15px_rgba(0,240,255,0.15)] translate-x-1'
                          : 'bg-slate-900/60 border-slate-800 hover:border-slate-700'
                      }`}
                    >
                      <div className="flex items-center justify-between">
                        <span className="font-mono text-xs font-bold text-cyan-400">{inc.id}</span>
                        <SeverityBadge level={inc.severity} size="sm" />
                      </div>

                      <h4 className="font-mono text-xs font-bold text-slate-200 mt-1 line-clamp-1">
                        {inc.title}
                      </h4>

                      <div className="flex items-center justify-between text-[11px] font-mono text-slate-500 mt-2">
                        <span className="truncate max-w-[140px]">{inc.affectedUser}</span>
                        <span
                          className={`px-1.5 py-0.5 rounded font-bold uppercase text-[9px] ${
                            inc.status === 'CONTAINED'
                              ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
                              : inc.status === 'RESOLVED'
                              ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40'
                              : inc.status === 'INVESTIGATING'
                              ? 'bg-amber-500/20 text-amber-300 border border-amber-500/40'
                              : 'bg-rose-500/20 text-rose-300 border border-rose-500/40'
                          }`}
                        >
                          {inc.status}
                        </span>
                      </div>
                    </div>
                  );
                })
              )}
            </div>
          </div>
        </div>

        {/* Right Column: Detailed Incident Record (7 cols) */}
        {active && (
          <div className="lg:col-span-7 space-y-4">
            <div className="p-6 rounded-2xl bg-[#070C18] border border-slate-800 shadow-cyber-card space-y-5">
              {/* Ticket Top Banner */}
              <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-4 border-b border-slate-800 gap-3">
                <div>
                  <div className="flex items-center space-x-2">
                    <span className="text-base font-mono font-bold text-cyan-400">{active.id}</span>
                    <SeverityBadge level={active.severity} size="sm" />
                    <ThreatBadge category={active.threatType} size="sm" />
                  </div>
                  <h2 className="text-base font-mono font-bold text-white mt-1">
                    {active.title}
                  </h2>
                </div>

                {/* Status Switcher */}
                <div className="flex items-center space-x-1.5 font-mono text-xs">
                  <span className="text-slate-500 text-[11px] mr-1">Status:</span>
                  {(['DETECTED', 'INVESTIGATING', 'CONTAINED', 'RESOLVED'] as const).map((st) => {
                    const isCurrent = active.status === st;
                    return (
                      <button
                        key={st}
                        onClick={() => updateIncidentStatus(active.id, st)}
                        className={`px-2.5 py-1 rounded text-[10px] font-bold uppercase border transition-all ${
                          isCurrent
                            ? st === 'RESOLVED'
                              ? 'bg-emerald-500/20 text-emerald-300 border-emerald-500/50 shadow-[0_0_12px_rgba(16,185,129,0.3)]'
                              : st === 'CONTAINED'
                              ? 'bg-cyan-500/20 text-cyan-300 border-cyan-500/50 shadow-[0_0_12px_rgba(0,240,255,0.3)]'
                              : st === 'INVESTIGATING'
                              ? 'bg-amber-500/20 text-amber-300 border-amber-500/50 shadow-[0_0_12px_rgba(245,158,11,0.3)]'
                              : 'bg-rose-500/20 text-rose-300 border-rose-500/50 shadow-[0_0_12px_rgba(244,63,94,0.3)]'
                            : 'bg-slate-900 text-slate-400 border-slate-800 hover:border-slate-750 hover:text-white'
                        }`}
                      >
                        {isCurrent && <span className="inline-block w-1.5 h-1.5 rounded-full bg-current mr-1 animate-pulse" />}
                        {st}
                      </button>
                    );
                  })}
                </div>
              </div>

              {/* Metadata strip */}
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 p-3 rounded-xl bg-slate-950 border border-slate-850 font-mono text-xs">
                <div>
                  <span className="text-[10px] text-slate-500 uppercase block">Target User</span>
                  <span className="text-slate-200 font-bold truncate block">{active.affectedUser}</span>
                </div>
                <div>
                  <span className="text-[10px] text-slate-500 uppercase block">Source Ingestion</span>
                  <span className="text-slate-200 font-bold block">{active.source}</span>
                </div>
                <div>
                  <span className="text-[10px] text-slate-500 uppercase block">Detection Time</span>
                  <span className="text-slate-200 font-bold block">{active.detectionTime}</span>
                </div>
                <div>
                  <span className="text-[10px] text-slate-500 uppercase block">Risk Score</span>
                  <span className="text-rose-400 font-bold block">{active.riskScore}/100</span>
                </div>
              </div>

              {/* Forensic Timeline Section */}
              <div className="space-y-3">
                <h4 className="text-xs font-mono font-bold uppercase tracking-wider text-slate-300 flex items-center">
                  <Clock className="w-3.5 h-3.5 text-cyan-400 mr-1.5" />
                  Forensic Incident Timeline
                </h4>

                <div className="space-y-2 border-l-2 border-slate-800 pl-4 ml-2 max-h-[220px] overflow-y-auto pr-1">
                  {active.timeline.map((event) => (
                    <div key={event.id} className="relative group">
                      <div className="absolute -left-[21px] top-1.5 w-2.5 h-2.5 rounded-full bg-cyan-400 ring-4 ring-[#070C18]" />
                      <div className="p-2.5 rounded-lg bg-slate-950/70 border border-slate-850 font-mono text-xs flex items-center justify-between">
                        <span className="text-slate-200">{event.event}</span>
                        <span className="text-[10px] text-slate-500 ml-2 shrink-0">{event.time}</span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {/* Response Actions Executed */}
              <div className="space-y-2">
                <h4 className="text-xs font-mono font-bold uppercase tracking-wider text-slate-300 flex items-center">
                  <ShieldCheck className="w-3.5 h-3.5 text-emerald-400 mr-1.5" />
                  SOAR Containment Playbook Actions
                </h4>

                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 font-mono text-xs">
                  {active.responseActions.map((act) => (
                    <div
                      key={act.id}
                      className="p-2.5 rounded-lg bg-slate-950/80 border border-emerald-500/20 text-slate-300 flex items-center space-x-2"
                    >
                      <span className="text-emerald-400 font-bold">✓</span>
                      <span className="text-emerald-300 text-[11px] font-semibold truncate">{act.action}</span>
                    </div>
                  ))}
                </div>
              </div>

              {/* Action Bar */}
              <div className="pt-3 border-t border-slate-800 flex items-center justify-between">
                <button
                  onClick={() => setCopilotOpen(true)}
                  className="px-4 py-2 rounded-xl bg-slate-800 hover:bg-slate-750 text-cyan-300 border border-cyan-500/30 text-xs font-mono font-bold flex items-center space-x-2 transition-colors"
                >
                  <MessageSquare className="w-3.5 h-3.5" />
                  <span>Explain with AI Copilot</span>
                </button>

                {active.status === 'RESOLVED' ? (
                  <button
                    onClick={() => updateIncidentStatus(active.id, 'INVESTIGATING')}
                    className="px-4 py-2 rounded-xl bg-slate-800 hover:bg-slate-750 text-amber-300 border border-amber-500/30 text-xs font-mono font-bold transition-all flex items-center space-x-1.5"
                  >
                    <RotateCcw className="w-3.5 h-3.5" />
                    <span>Reopen Incident</span>
                  </button>
                ) : (
                  <button
                    onClick={() => updateIncidentStatus(active.id, 'RESOLVED')}
                    className="px-4 py-2 rounded-xl bg-emerald-500 hover:bg-emerald-400 text-slate-950 text-xs font-mono font-bold transition-all shadow-[0_0_15px_rgba(16,185,129,0.3)] flex items-center space-x-1.5"
                  >
                    <CheckCircle2 className="w-3.5 h-3.5" />
                    <span>Mark Incident Resolved</span>
                  </button>
                )}
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
