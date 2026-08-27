// Ambient declaration for the desktop shell bridge injected by apps/desktop/preload.cjs.
// Present only when running inside the Electron app; undefined in a plain browser (the `serve` web UI).
export {};

// Side-effect CSS imports (webui styles + desktop chrome) — Vite handles these; tell tsc they resolve.
declare module "*.css";

declare global {
    interface VerdictDesktop {
        platform: string;
        minimize(): void;
        toggleMaximize(): void;
        close(): void;
        isMaximized(): Promise<boolean>;
        onMaximizeChange(cb: (maximized: boolean) => void): () => void;
    }
    interface Window {
        verdictDesktop?: VerdictDesktop;
    }
}
