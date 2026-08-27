// Ambient declaration for the desktop shell bridge injected by apps/desktop/preload.cjs.
// Present only when running inside the Electron app; undefined in a plain browser (the `serve` web UI).
export {};

// Side-effect CSS imports (webui styles + desktop chrome) — Vite handles these; tell tsc they resolve.
declare module "*.css";

declare global {
    interface AttBrowserNavState {
        url: string;
        title: string;
        canGoBack: boolean;
        canGoForward: boolean;
        loading: boolean;
    }
    interface AttBrowserCapture {
        ok: boolean;
        path?: string;
        count?: number;
        host?: string;
        error?: string;
    }
    interface AttendedBrowserBridge {
        open(url: string): Promise<void>;
        setBounds(b: { x: number; y: number; width: number; height: number }): void;
        close(): void;
        navigate(url: string): Promise<void>;
        back(): void;
        forward(): void;
        reload(): void;
        capture(assessmentId?: string): Promise<AttBrowserCapture>;
        onNavigated(cb: (s: AttBrowserNavState) => void): () => void;
    }
    interface DesktopSettings {
        provider: "claude-cli" | "openai";
        baseURL?: string;
        apiKey?: string;
        deepModel?: string;
        lightModel?: string;
        browserPath?: string;
    }
    interface SettingsBridge {
        get(): Promise<DesktopSettings>;
        set(s: DesktopSettings): Promise<DesktopSettings>;
    }
    interface VerdictDesktop {
        platform: string;
        minimize(): void;
        toggleMaximize(): void;
        close(): void;
        isMaximized(): Promise<boolean>;
        onMaximizeChange(cb: (maximized: boolean) => void): () => void;
        browser: AttendedBrowserBridge;
        settings: SettingsBridge;
    }
    interface Window {
        verdictDesktop?: VerdictDesktop;
    }
}
