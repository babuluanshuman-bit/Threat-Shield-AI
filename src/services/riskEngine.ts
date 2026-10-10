import { RiskLevel, ThreatIndicator } from '../types/cyberguard';

export const getRiskLevel = (score: number): RiskLevel => {
  if (score <= 20) return 'SAFE';
  if (score <= 40) return 'LOW';
  if (score <= 60) return 'MEDIUM';
  if (score <= 80) return 'HIGH';
  return 'CRITICAL';
};

export const getRiskTheme = (level: RiskLevel) => {
  switch (level) {
    case 'SAFE':
      return {
        label: 'SAFE',
        color: '#10B981',
        textClass: 'text-emerald-400',
        bgClass: 'bg-emerald-500/10',
        borderClass: 'border-emerald-500/30',
        glowClass: 'shadow-[0_0_15px_rgba(16,185,129,0.35)]',
        badgeBg: 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40',
        gradient: 'from-emerald-500 to-teal-400',
      };
    case 'LOW':
      return {
        label: 'LOW RISK',
        color: '#34D399',
        textClass: 'text-teal-400',
        bgClass: 'bg-teal-500/10',
        borderClass: 'border-teal-500/30',
        glowClass: 'shadow-[0_0_15px_rgba(20,184,166,0.3)]',
        badgeBg: 'bg-teal-500/20 text-teal-300 border-teal-500/40',
        gradient: 'from-teal-500 to-cyan-400',
      };
    case 'MEDIUM':
      return {
        label: 'MEDIUM RISK',
        color: '#F59E0B',
        textClass: 'text-amber-400',
        bgClass: 'bg-amber-500/10',
        borderClass: 'border-amber-500/30',
        glowClass: 'shadow-[0_0_15px_rgba(245,158,11,0.35)]',
        badgeBg: 'bg-amber-500/20 text-amber-300 border-amber-500/40',
        gradient: 'from-amber-500 to-yellow-400',
      };
    case 'HIGH':
      return {
        label: 'HIGH RISK',
        color: '#F97316',
        textClass: 'text-orange-400',
        bgClass: 'bg-orange-500/10',
        borderClass: 'border-orange-500/30',
        glowClass: 'shadow-[0_0_20px_rgba(249,115,22,0.4)]',
        badgeBg: 'bg-orange-500/20 text-orange-300 border-orange-500/40',
        gradient: 'from-orange-500 to-amber-500',
      };
    case 'CRITICAL':
    default:
      return {
        label: 'CRITICAL THREAT',
        color: '#EF4444',
        textClass: 'text-rose-400',
        bgClass: 'bg-rose-500/10',
        borderClass: 'border-rose-500/40',
        glowClass: 'shadow-[0_0_25px_rgba(239,68,68,0.5)]',
        badgeBg: 'bg-rose-500/25 text-rose-300 border-rose-500/50',
        gradient: 'from-rose-600 to-red-500',
      };
  }
};

export const calculateExplainableRisk = (
  baseScore: number,
  indicators: ThreatIndicator[]
): {
  finalScore: number;
  level: RiskLevel;
  totalPositiveImpact: number;
  totalNegativeImpact: number;
} => {
  let score = baseScore;
  let totalPositiveImpact = 0;
  let totalNegativeImpact = 0;

  indicators.forEach((ind) => {
    score += ind.impact;
    if (ind.impact > 0) totalPositiveImpact += ind.impact;
    else totalNegativeImpact += ind.impact;
  });

  const finalScore = Math.min(100, Math.max(0, score));
  return {
    finalScore,
    level: getRiskLevel(finalScore),
    totalPositiveImpact,
    totalNegativeImpact,
  };
};
