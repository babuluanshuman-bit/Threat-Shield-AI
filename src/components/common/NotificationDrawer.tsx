import React from 'react';
import { useCyberGuard } from '../../context/CyberGuardContext';
import {
  Bell,
  X,
  CheckCircle,
  ExternalLink,
  ShieldAlert,
  AlertTriangle,
  Trash2
} from 'lucide-react';
import { SeverityBadge } from './ThreatBadge';

export const NotificationDrawer: React.FC = () => {
  const {
    notificationsOpen,
    setNotificationsOpen,
    notifications,
    markNotificationRead,
    markAllNotificationsRead,
    incidents,
    setSelectedIncident,
    setActiveTab,
  } = useCyberGuard();

  if (!notificationsOpen) return null;

  const handleOpenIncident = (incId?: string) => {
    if (incId) {
      const match = incidents.find((i) => i.id === incId);
      if (match) setSelectedIncident(match);
    }
    setActiveTab('dashboard');
    setNotificationsOpen(false);
  };

  return (
    <div className="fixed inset-y-0 right-0 z-50 w-full sm:w-[420px] bg-[#070C18] border-l border-slate-800 shadow-[-10px_0_40px_rgba(0,0,0,0.8)] flex flex-col animate-slide-up">
      {/* Header */}
      <div className="p-4 border-b border-slate-800 bg-slate-950/80 flex items-center justify-between">
        <div className="flex items-center space-x-2">
          <div className="p-1.5 rounded-lg bg-cyan-500/10 border border-cyan-500/30 text-cyan-400">
            <Bell className="w-4 h-4" />
          </div>
          <div>
            <h3 className="font-mono text-xs font-bold text-white uppercase tracking-wider">
              Security Notification Center
            </h3>
            <p className="text-[11px] text-slate-400 font-sans">
              Real-time threat alerts & autonomous SOAR triggers
            </p>
          </div>
        </div>

        <div className="flex items-center space-x-2">
          <button
            onClick={markAllNotificationsRead}
            className="text-[11px] font-mono text-cyan-400 hover:text-cyan-300"
            title="Mark all as read"
          >
            Mark all read
          </button>
          <button
            onClick={() => setNotificationsOpen(false)}
            className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-white"
          >
            <X className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* Notifications List */}
      <div className="flex-1 overflow-y-auto p-4 space-y-3">
        {notifications.map((notif) => (
          <div
            key={notif.id}
            className={`p-3.5 rounded-xl border transition-all ${
              notif.read
                ? 'bg-slate-900/40 border-slate-850 opacity-75'
                : 'bg-slate-900/90 border-cyan-500/30 shadow-[0_0_15px_rgba(0,240,255,0.08)]'
            }`}
          >
            <div className="flex items-start justify-between">
              <div className="flex items-center space-x-2">
                <SeverityBadge level={notif.severity} size="sm" pulse={!notif.read} />
                <span className="text-[10px] font-mono text-slate-500">
                  {notif.timestamp}
                </span>
              </div>
              {!notif.read && (
                <button
                  onClick={() => markNotificationRead(notif.id)}
                  className="text-[10px] font-mono text-slate-400 hover:text-cyan-400"
                >
                  Mark read
                </button>
              )}
            </div>

            <h5 className="font-mono text-xs font-bold text-slate-200 mt-2">
              {notif.title}
            </h5>
            <p className="text-xs text-slate-300 font-sans mt-1 leading-relaxed">
              {notif.message}
            </p>

            {notif.actionTaken && (
              <div className="mt-2.5 flex items-center justify-between text-[11px] font-mono">
                <span className="text-emerald-400 bg-emerald-500/10 px-2 py-0.5 rounded border border-emerald-500/20">
                  ✓ {notif.actionTaken}
                </span>
                {notif.incidentId && (
                  <button
                    onClick={() => handleOpenIncident(notif.incidentId)}
                    className="text-cyan-400 hover:text-cyan-300 flex items-center space-x-1"
                  >
                    <span>View Ticket</span>
                    <ExternalLink className="w-3 h-3" />
                  </button>
                )}
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
};
