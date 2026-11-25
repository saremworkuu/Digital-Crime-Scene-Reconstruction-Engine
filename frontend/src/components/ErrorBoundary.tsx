import React, { Component, ErrorInfo, ReactNode } from 'react';

interface Props {
  children: ReactNode;
}

interface State {
  hasError: boolean;
}

const RELOAD_STORAGE_KEY = 'dcsre_auto_reload_ts';

export class ErrorBoundary extends Component<Props, State> {
  public state: State = {
    hasError: false,
  };

  public static getDerivedStateFromError(error: Error): State {
    // If it's a MetaMask or external wallet extension error, ignore it
    const msg = error?.message || '';
    if (msg.includes('MetaMask') || msg.includes('ethereum') || msg.includes('Failed to connect to MetaMask')) {
      return { hasError: false };
    }
    return { hasError: true };
  }

  public componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    const msg = error?.message || '';
    if (msg.includes('MetaMask') || msg.includes('ethereum')) {
      return;
    }

    console.error('Uncaught error in component tree, reloading workspace:', error, errorInfo);

    if (typeof window !== 'undefined') {
      try {
        const now = Date.now();
        const lastReload = Number(sessionStorage.getItem(RELOAD_STORAGE_KEY) || '0');
        if (now - lastReload > 3000) {
          sessionStorage.setItem(RELOAD_STORAGE_KEY, String(now));
          window.location.reload();
        }
      } catch {
        window.location.reload();
      }
    }
  }

  public render() {
    if (this.state.hasError) {
      return null;
    }

    return this.props.children;
  }
}
