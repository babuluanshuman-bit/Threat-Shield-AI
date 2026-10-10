import React, { Component, ErrorInfo, ReactNode } from 'react';
import { AlertTriangle, RefreshCw, Home } from 'lucide-react';

interface Props {
  children: ReactNode;
}

interface State {
  hasError: boolean;
  error: Error | null;
}

export class ErrorBoundary extends Component<Props, State> {
  public state: State = {
    hasError: false,
    error: null,
  };

  public static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error };
  }

  public componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    console.error('Threat Lens ErrorBoundary caught an error:', error, errorInfo);
  }

  private handleReset = () => {
    this.setState({ hasError: false, error: null });
    window.location.reload();
  };

  public render() {
    if (this.state.hasError) {
      return (
        <div className="min-h-screen bg-[#050811] text-slate-100 flex items-center justify-center p-6">
          <div className="max-w-lg w-full p-6 sm:p-8 rounded-2xl bg-[#0B1120] border border-rose-500/40 shadow-[0_0_40px_rgba(244,63,94,0.2)] text-center space-y-4">
            <div className="w-14 h-14 rounded-2xl bg-rose-500/10 border border-rose-500/30 text-rose-400 mx-auto flex items-center justify-center">
              <AlertTriangle className="w-8 h-8" />
            </div>

            <h2 className="text-xl font-mono font-bold text-white tracking-wide">
              APPLICATION RUNTIME NOTICE
            </h2>

            <p className="text-xs text-slate-300 font-sans leading-relaxed">
              An unexpected interface state occurred. The SOC defense telemetry and saved configurations remain safe.
            </p>

            {this.state.error && (
              <div className="p-3 rounded-xl bg-slate-950 border border-slate-800 text-left font-mono text-xs text-rose-300 max-h-36 overflow-y-auto">
                {this.state.error.message || String(this.state.error)}
              </div>
            )}

            <div className="pt-2 flex items-center justify-center space-x-3">
              <button
                onClick={this.handleReset}
                className="px-5 py-2.5 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-slate-950 font-mono font-bold text-xs uppercase tracking-wider shadow-lg flex items-center space-x-2"
              >
                <RefreshCw className="w-4 h-4 text-slate-950" />
                <span>Reload Threat Lens</span>
              </button>
            </div>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}
