import React from 'react';
import { RiskLevel } from '../../types/cyberguard';
import { getRiskLevel, getRiskTheme } from '../../services/riskEngine';

interface RiskGaugeProps {
  score: number;
  size?: 'sm' | 'md' | 'lg';
  showLabel?: boolean;
  subtext?: string;
  className?: string;
}

export const RiskGauge: React.FC<RiskGaugeProps> = ({
  score,
  size = 'md',
  showLabel = true,
  subtext,
  className = '',
}) => {
  const level: RiskLevel = getRiskLevel(score);
  const theme = getRiskTheme(level);

  // Dimensions based on size
  const config = {
    sm: { width: 120, height: 75, strokeWidth: 8, radius: 48, fontSize: 'text-xl', labelSize: 'text-xs' },
    md: { width: 180, height: 110, strokeWidth: 12, radius: 72, fontSize: 'text-3xl', labelSize: 'text-xs' },
    lg: { width: 240, height: 145, strokeWidth: 16, radius: 96, fontSize: 'text-4xl', labelSize: 'text-sm' },
  }[size];

  const cx = config.width / 2;
  const cy = config.height;
  const r = config.radius;
  const startX = cx - r;
  const endX = cx + r;
  const pathD = `M ${startX} ${cy} A ${r} ${r} 0 0 1 ${endX} ${cy}`;

  // Arc calculations (180 degree semi-circle)
  // Exact circumference for semi-circle = Math.PI * radius
  const circumference = Math.PI * r;
  const clampedScore = Math.min(100, Math.max(0, score));
  // When score is 0, offset by circumference + strokeWidth to hide round cap entirely; when 100, offset is 0
  const strokeDashoffset = clampedScore === 0 
    ? circumference + config.strokeWidth 
    : circumference - (clampedScore / 100) * circumference;

  return (
    <div className={`flex flex-col items-center justify-center relative select-none ${className}`}>
      <div className="relative" style={{ width: config.width, height: config.height }}>
        <svg
          width={config.width}
          height={config.height}
          viewBox={`0 0 ${config.width} ${config.height + 14}`}
          className="overflow-visible"
        >
          <defs>
            <linearGradient id={`gauge-grad-${level}`} x1="0%" y1="0%" x2="100%" y2="0%">
              <stop offset="0%" stopColor="#10B981" />
              <stop offset="35%" stopColor="#F59E0B" />
              <stop offset="70%" stopColor="#F97316" />
              <stop offset="100%" stopColor="#EF4444" />
            </linearGradient>
            <filter id="gauge-glow" x="-20%" y="-20%" width="140%" height="140%">
              <feGaussianBlur stdDeviation="3" result="blur" />
              <feComposite in="SourceGraphic" in2="blur" operator="over" />
            </filter>
          </defs>

          {/* Background Track */}
          <path
            d={pathD}
            fill="none"
            stroke="#1e293b"
            strokeWidth={config.strokeWidth}
            strokeLinecap="round"
          />

          {/* Tick marks */}
          {[0, 25, 50, 75, 100].map((tick, i) => {
            const angle = Math.PI - (tick / 100) * Math.PI;
            const x = cx + (r - config.strokeWidth - 6) * Math.cos(angle);
            const y = cy - (r - config.strokeWidth - 6) * Math.sin(angle);
            return (
              <circle
                key={i}
                cx={x}
                cy={y}
                r="1.5"
                fill="#475569"
              />
            );
          })}

          {/* Animated Value Arc */}
          <path
            d={pathD}
            fill="none"
            stroke={theme.color}
            strokeWidth={config.strokeWidth}
            strokeDasharray={circumference}
            strokeDashoffset={strokeDashoffset}
            strokeLinecap="round"
            filter="url(#gauge-glow)"
            style={{
              transition: 'stroke-dashoffset 0.8s cubic-bezier(0.16, 1, 0.3, 1), stroke 0.4s ease',
            }}
          />
        </svg>

        {/* Center Numbers */}
        <div
          className="absolute inset-0 flex flex-col items-center justify-end"
          style={{ paddingBottom: '4px' }}
        >
          <div className="flex items-baseline space-x-1">
            <span className={`font-mono font-extrabold ${config.fontSize} ${theme.textClass} tracking-tight drop-shadow`}>
              {score}
            </span>
            <span className="text-slate-500 font-mono text-xs">/100</span>
          </div>
        </div>
      </div>

      {showLabel && (
        <div className="mt-2 text-center">
          <span
            className={`inline-flex items-center px-2.5 py-0.5 rounded-full font-mono font-semibold tracking-wider ${config.labelSize} ${theme.badgeBg} border shadow-sm`}
          >
            <span className="w-1.5 h-1.5 rounded-full mr-1.5 animate-pulse" style={{ backgroundColor: theme.color }} />
            {theme.label}
          </span>
          {subtext && <p className="text-[11px] text-slate-400 mt-1 font-mono">{subtext}</p>}
        </div>
      )}
    </div>
  );
};
