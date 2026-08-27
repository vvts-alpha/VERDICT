// Desktop renderer entry — a SEPARATE frontend build from the web (`serve`) UI. It reuses the shared view
// components by mounting webui's App, wrapped in the desktop-only chrome (custom title bar / window controls).
// The web build (@veritas/webui) never includes any of this, and the desktop UI can diverge freely from here.
import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { App } from "@veritas/webui";
import "@veritas/webui/styles.css";
import { DesktopChrome } from "./DesktopChrome";
import "./desktop.css";

const el = document.getElementById("root");
if (el) {
    createRoot(el).render(
        <StrictMode>
            <DesktopChrome>
                <App />
            </DesktopChrome>
        </StrictMode>,
    );
}
