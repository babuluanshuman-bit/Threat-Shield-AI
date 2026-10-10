import React from 'react';
import { RiskLevel, ThreatCategory } from '../../types/cyberguard';
import { getRiskTheme } from '../../services/riskEngine';
import {
  ShieldAlert,
  Mail,
  Link,
  Smartphone,
  UserX,
  Image as ImageIcon,
  Activity,
  KeyRound,
  FileCode,
  Network,
  AlertTriangle
} from 'lucide-react';

interface SeverityBadgeProps {
  level: RiskLevel;
  size?: 'sm' | 'md';
  pulse?: boolean;
}

export const SeverityBadge: React.FC<SeverityBadgeProps> = ({
  level,
  size = 'md',
  pulse = true,
}) => {
  const theme = getRiskTheme(level);
  const sizeClasses = size === 'sm' ? 'px-2 py-0.5 text-[10px]' : 'px-2.5 py-1 text-xs';

  return (
    <span
      className={`inline-flex items-center font-mono font-bold tracking-wider rounded-md border shadow-sm ${sizeClasses} ${theme.badgeBg}`}
    >
      {pulse && (
        <span
          className="w-1.5 h-1.5 rounded-full mr-1.5 animate-pulse"
          style={{ backgroundColor: theme.color }}
        />
      )}
      {theme.label}
    </span>
  );
};

interface ThreatBadgeProps {
  category: ThreatCategory;
  size?: 'sm' | 'md';
}

export const ThreatBadge: React.FC<ThreatBadgeProps> = ({ category, size = 'md' }) => {
  const getCategoryIcon = () => {
    switch (category) {
      case 'Phishing':
        return <Mail className="w-3.5 h-3.5 text-rose-400 mr-1.5" />;
      case 'Malicious URL':
        return <Link className="w-3.5 h-3.5 text-orange-400 mr-1.5" />;
      case 'Brand Impersonation':
        return <ShieldAlert className="w-3.5 h-3.5 text-purple-400 mr-1.5" />;
      case 'Account Takeover':
        return <UserX className="w-3.5 h-3.5 text-rose-400 mr-1.5" />;
      case 'Deepfake Media':
        return <ImageIcon className="w-3.5 h-3.5 text-cyan-400 mr-1.5" />;
      case 'Impossible Travel':
        return <Activity className="w-3.5 h-3.5 text-amber-400 mr-1.5" />;
      case 'Brute Force':
      case 'Credential Theft':
        return <KeyRound className="w-3.5 h-3.5 text-orange-400 mr-1.5" />;
      case 'Network Anomaly':
        return <Network className="w-3.5 h-3.5 text-cyan-400 mr-1.5" />;
      case 'Malicious File':
        return <FileCode className="w-3.5 h-3.5 text-rose-400 mr-1.5" />;
      case 'Social Engineering':
        return <Smartphone className="w-3.5 h-3.5 text-yellow-400 mr-1.5" />;
      default:
        return <AlertTriangle className="w-3.5 h-3.5 text-slate-400 mr-1.5" />;
    }
  };

  const sizeClasses = size === 'sm' ? 'px-2 py-0.5 text-[11px]' : 'px-2.5 py-1 text-xs';

  return (
    <span
      className={`inline-flex items-center font-mono font-medium rounded-md bg-slate-800/80 text-slate-200 border border-slate-700/80 ${sizeClasses}`}
    >
      {getCategoryIcon()}
      {category}
    </span>
  );
};
