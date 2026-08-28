// Preload for the VERDICT desktop shell. Runs with contextIsolation — exposes a minimal, safe bridge the
// renderer (the existing web UI) uses to render desktop chrome (custom title bar + window controls). Its mere
// presence (window.verdictDesktop) is how the web UI knows it is running inside the app vs. a plain browser.
const { contextBridge, ipcRenderer } = require("electron");

contextBridge.exposeInMainWorld("verdictDesktop", {
    platform: process.platform,
    minimize: () => ipcRenderer.send("win:minimize"),
    toggleMaximize: () => ipcRenderer.send("win:toggle-maximize"),
    close: () => ipcRenderer.send("win:close"),
    /** Focus the app's own web contents. The attended-browser native view steals OS focus; calling this when the
     *  pointer enters the title bar pre-empts the "first click just refocuses" quirk so chrome buttons act on click 1. */
    focusChrome: () => ipcRenderer.send("win:focus-chrome"),
    isMaximized: () => ipcRenderer.invoke("win:is-maximized"),
    /** Subscribe to maximize/unmaximize; returns an unsubscribe fn. */
    onMaximizeChange: (cb) => {
        const h = (_e, v) => cb(!!v);
        ipcRenderer.on("win:maximize-changed", h);
        return () => ipcRenderer.removeListener("win:maximize-changed", h);
    },

    // Attended embedded browser (Electron's own Chromium as an in-window view for human login / session capture).
    browser: {
        open: (url) => ipcRenderer.invoke("attbrowser:open", url),
        setBounds: (b) => ipcRenderer.send("attbrowser:set-bounds", b),
        close: () => ipcRenderer.send("attbrowser:close"),
        navigate: (url) => ipcRenderer.invoke("attbrowser:navigate", url),
        back: () => ipcRenderer.send("attbrowser:back"),
        forward: () => ipcRenderer.send("attbrowser:forward"),
        reload: () => ipcRenderer.send("attbrowser:reload"),
        capture: (assessmentId) => ipcRenderer.invoke("attbrowser:capture", assessmentId),
        onNavigated: (cb) => {
            const h = (_e, s) => cb(s);
            ipcRenderer.on("attbrowser:navigated", h);
            return () => ipcRenderer.removeListener("attbrowser:navigated", h);
        },
    },

    // In-app settings (LLM provider / Deep + Light models / browser path).
    settings: {
        get: () => ipcRenderer.invoke("settings:get"),
        set: (s) => ipcRenderer.invoke("settings:set", s),
    },
});
