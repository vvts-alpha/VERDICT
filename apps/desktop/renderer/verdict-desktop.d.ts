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
        localStorage?: number;
        host?: string;
        header?: string;
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
        provider: import("../src/model-providers").ModelProvider;
        baseURL?: string;
        apiKey?: string;
        deepModel?: string;
        lightModel?: string;
        browserPath?: string;
        proxy?: string;
        burpScan?: boolean;
        burpApi?: string;
        burpApiKey?: string;
        burpResourcePool?: string;
        burpAuditApi?: string;
        burpAuditToken?: string;
        oobProvider?: "off" | "interactsh" | "burp";
        interactshServer?: string;
        interactshToken?: string;
        operatorContext?: string;
    }
    interface SettingsBridge {
        get(): Promise<DesktopSettings>;
        check(s?: DesktopSettings): Promise<import("@veritas/core").ReadinessCheck[]>;
        set(s: DesktopSettings): Promise<DesktopSettings>;
    }
    interface AppInfo {
        version: string;
        electron: string;
        node: string;
        chrome: string;
    }
    interface VerdictDesktop {
        platform: string;
        minimize(): void;
        toggleMaximize(): void;
        close(): void;
        focusChrome(): void;
        isMaximized(): Promise<boolean>;
        onMaximizeChange(cb: (maximized: boolean) => void): () => void;
        browser: AttendedBrowserBridge;
        settings: SettingsBridge;
        app: { info(): Promise<AppInfo> };
    }
    interface Window {
        verdictDesktop?: VerdictDesktop;
    }
}
