import React, { Component, ErrorInfo, ReactNode } from 'react';
import { AlertTriangle, RefreshCw } from 'lucide-react';

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
    // If it's a MetaMask or external wallet extension error, ignore it
    const msg = error?.message || '';
    if (msg.includes('MetaMask') || msg.includes('ethereum') || msg.includes('Failed to connect to MetaMask')) {
      return { hasError: false, error: null };
    }
    return { hasError: true, error };
  }

  public componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    const msg = error?.message || '';
    if (!msg.includes('MetaMask') && !msg.includes('ethereum')) {
      console.error('Uncaught error in component tree:', error, errorInfo);
    }
  }

  public render() {
    if (this.state.hasError && this.state.error) {
      return (
        <div className="min-h-screen bg-[#0e0d0d] text-[#fafaf9] flex items-center justify-center p-6">
          <div className="max-w-md w-full bg-[#161413] border border-[#2b2523] rounded-2xl p-6 space-y-4 text-center shadow-2xl backdrop-blur-xl">
            <div className="w-12 h-12 rounded-xl bg-[#2a140d] border border-[#ea580c]/40 flex items-center justify-center text-[#f95721] mx-auto">
              <AlertTriangle className="w-6 h-6" />
            </div>
            <h2 className="text-base font-semibold text-[#fafaf9]">
              Application Recovery Triggered
            </h2>
            <p className="text-xs text-[#a8a29e]">
              An unexpected condition occurred in the rendering pipeline. The forensic workspace can be restored safely without data loss.
            </p>
            <div className="p-3 bg-[#0d0c0c] rounded-xl border border-[#282321] text-left font-mono text-[11px] text-[#fca5a5] overflow-x-auto max-h-32">
              {this.state.error.message}
            </div>
            <button
              onClick={() => {
                this.setState({ hasError: false, error: null });
                window.location.reload();
              }}
              className="px-4 py-2 bg-[#f95721] hover:bg-[#ea580c] text-white text-xs font-semibold rounded-lg transition-all inline-flex items-center gap-1.5 shadow-[0_0_12px_rgba(249,87,33,0.3)] cursor-pointer"
            >
              <RefreshCw className="w-3.5 h-3.5" />
              <span>Reload Workspace</span>
            </button>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}
