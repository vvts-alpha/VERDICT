// Display preferences pane (serve mode). The desktop app keeps its own Settings view for backend
// config (LLM/browser); this pane holds UI-level prefs that apply to both — currently the display
// language, persisted in localStorage and shared through LangProvider.
import { useT } from "../i18n";
import { LanguageSelect } from "../i18n";
import { SlidersHorizontal } from "lucide-react";
import { Card, CardContent } from "./ui/card";

export function Settings() {
  const t = useT();
  return (
    <div className="mx-auto w-full max-w-[1100px] space-y-4 px-5 py-6">
      <header className="flex items-center justify-between border-b border-border pb-4">
        <h1 className="flex items-center gap-2 text-base font-semibold">
          <SlidersHorizontal className="size-4" /> {t("Settings")}
        </h1>
      </header>
      <Card>
        <CardContent className="p-4">
          <div className="flex items-center justify-between gap-4">
            <div>
              <p className="text-sm font-medium">{t("Display language")}</p>
              <p className="mt-0.5 text-xs text-muted-foreground">{t("Applies to the whole interface immediately; saved on this device.")}</p>
            </div>
            <LanguageSelect />
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
