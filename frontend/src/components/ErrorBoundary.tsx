import { Component, type ErrorInfo, type ReactNode } from 'react';

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
    console.error('Uncaught error in component tree:', error, errorInfo);
  }

  public render() {
    if (this.state.hasError) {
      return (
        <div className="min-h-screen bg-[var(--surface)] flex items-center justify-center p-8">
          <div className="max-w-xl w-full border-2 border-[var(--text-primary)] bg-[var(--surface-raised)] p-8 shadow-[8px_8px_0px_#111111] space-y-4">
            <div className="flex items-center gap-2">
              <span className="w-3 h-3 bg-[var(--accent)] inline-block" />
              <span className="font-mono text-xs uppercase font-bold text-[var(--accent)]">
                Application Exception Intercepted
              </span>
            </div>
            <h1 className="font-display text-2xl font-bold uppercase text-[var(--text-primary)]">
              An Architectural Error Occurred
            </h1>
            <p className="text-xs text-[var(--text-secondary)] font-mono">
              {this.state.error?.message || 'Unknown runtime error'}
            </p>
            <div className="pt-4 flex gap-3">
              <button
                onClick={() => window.location.reload()}
                className="px-4 py-2 bg-[var(--text-primary)] text-[var(--surface)] font-mono text-xs font-bold uppercase hover:bg-[var(--accent)]"
              >
                Reload Application
              </button>
              <button
                onClick={() => this.setState({ hasError: false, error: null })}
                className="px-4 py-2 border border-[var(--border)] font-mono text-xs font-bold uppercase hover:bg-[var(--surface)]"
              >
                Dismiss & Retry
              </button>
            </div>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}
