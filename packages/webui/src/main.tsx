import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { App } from "./App";
import { LangProvider } from "./i18n";
import "./styles.css";

const el = document.getElementById("root");
if (el) {
  createRoot(el).render(
    <StrictMode>
      <LangProvider>
        <App />
      </LangProvider>
    </StrictMode>,
  );
}
