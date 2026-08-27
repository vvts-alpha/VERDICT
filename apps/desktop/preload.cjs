// Preload for the VERDICT desktop shell. Runs with contextIsolation — exposes a minimal, safe bridge the
// renderer (the existing web UI) uses to render desktop chrome (custom title bar + window controls). Its mere
// presence (window.verdictDesktop) is how the web UI knows it is running inside the app vs. a plain browser.
const { contextBridge, ipcRenderer } = require("electron");

contextBridge.exposeInMainWorld("verdictDesktop", {
    platform: process.platform,
    minimize: () => ipcRenderer.send("win:minimize"),
    toggleMaximize: () => ipcRenderer.send("win:toggle-maximize"),
    close: () => ipcRenderer.send("win:close"),
    isMaximized: () => ipcRenderer.invoke("win:is-maximized"),
    /** Subscribe to maximize/unmaximize; returns an unsubscribe fn. */
    onMaximizeChange: (cb) => {
        const h = (_e, v) => cb(!!v);
        ipcRenderer.on("win:maximize-changed", h);
        return () => ipcRenderer.removeListener("win:maximize-changed", h);
    },
});
