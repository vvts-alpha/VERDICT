import type { ReactNode } from "react";
import { cn } from "cn";
import { ChevronRight } from "lucide-react";
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "./ui/collapsible";

// Card-wrapped collapsible section — the shared disclosure for optional form groups and operator
// panels. Sections open independently (multiple can be open at once), matching the old <details>.
export function Disclosure({
    title,
    defaultOpen = false,
    className,
    triggerClassName,
    children,
}: {
    title: ReactNode;
    defaultOpen?: boolean;
    className?: string;
    triggerClassName?: string;
    children: ReactNode;
}) {
    return (
        <Collapsible defaultOpen={defaultOpen} className={cn("my-3 rounded-lg border border-border bg-card px-3 py-2", className)}>
            <CollapsibleTrigger type="button" className={cn("group flex w-full cursor-pointer items-center gap-1.5 text-left text-primary", triggerClassName)}>
                <ChevronRight className="size-3.5 shrink-0 transition-transform group-data-[state=open]:rotate-90" />
                {title}
            </CollapsibleTrigger>
            <CollapsibleContent>{children}</CollapsibleContent>
        </Collapsible>
    );
}
