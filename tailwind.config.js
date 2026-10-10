/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        cyber: {
          dark: '#050811',
          panel: '#0B1120',
          surface: '#111B2E',
          card: 'rgba(15, 23, 42, 0.75)',
          border: 'rgba(56, 189, 248, 0.15)',
          cyan: '#00F0FF',
          blue: '#3B82F6',
          purple: '#8B5CF6',
          pink: '#EC4899',
          danger: '#EF4444',
          warning: '#F59E0B',
          success: '#10B981',
          muted: '#94A3B8'
        }
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', 'sans-serif'],
        mono: ['JetBrains Mono', 'Fira Code', 'Consolas', 'monospace']
      },
      boxShadow: {
        'cyan-glow': '0 0 25px -5px rgba(0, 240, 255, 0.35)',
        'blue-glow': '0 0 25px -5px rgba(59, 130, 246, 0.35)',
        'red-glow': '0 0 25px -5px rgba(239, 68, 68, 0.45)',
        'emerald-glow': '0 0 25px -5px rgba(16, 185, 129, 0.35)',
        'cyber-card': '0 8px 32px 0 rgba(0, 0, 0, 0.37)'
      },
      animation: {
        'pulse-slow': 'pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'scanline': 'scanline 8s linear infinite',
        'radar-sweep': 'radar 4s linear infinite',
        'fade-in': 'fadeIn 0.3s ease-out forwards',
        'slide-up': 'slideUp 0.4s ease-out forwards',
      },
      keyframes: {
        scanline: {
          '0%': { transform: 'translateY(-100%)' },
          '100%': { transform: 'translateY(1000%)' },
        },
        radar: {
          '0%': { transform: 'rotate(0deg)' },
          '100%': { transform: 'rotate(360deg)' },
        },
        fadeIn: {
          '0%': { opacity: '0', transform: 'scale(0.98)' },
          '100%': { opacity: '1', transform: 'scale(1)' },
        },
        slideUp: {
          '0%': { opacity: '0', transform: 'translateY(12px)' },
          '100%': { opacity: '1', transform: 'translateY(0)' },
        }
      }
    },
  },
  plugins: [],
}
