"use client"

import * as React from "react"
import { cn } from "cn"
import { GripVerticalIcon } from "lucide-react"
import { Group, Panel, Separator } from "react-resizable-panels"

const ResizablePanelGroup = React.forwardRef<HTMLDivElement, React.ComponentProps<typeof Group>>(
  ({ className, ...props }, ref) => {
    return (
      <Group
        elementRef={ref}
        data-slot="resizable-panel-group"
        className={cn("flex h-full w-full data-[orientation=vertical]:flex-col", className)}
        {...props}
      />
    )
  }
)
ResizablePanelGroup.displayName = "ResizablePanelGroup"

const ResizablePanel = React.forwardRef<HTMLDivElement, React.ComponentProps<typeof Panel>>(
  ({ ...props }, ref) => {
    return <Panel elementRef={ref} data-slot="resizable-panel" {...props} />
  }
)
ResizablePanel.displayName = "ResizablePanel"

const ResizableHandle = React.forwardRef<
  HTMLDivElement,
  React.ComponentProps<typeof Separator> & { withHandle?: boolean }
>(({ withHandle, className, ...props }, ref) => {
  return (
    <Separator
      elementRef={ref}
      data-slot="resizable-handle"
      className={cn(
        "relative flex w-px items-center justify-center bg-border transition-colors outline-none after:absolute after:inset-y-0 after:left-1/2 after:w-4 after:-translate-x-1/2 after:content-[''] hover:bg-ring/60 focus-visible:ring-1 focus-visible:ring-ring data-[separator]:[--sep:var(--border)]",
        className
      )}
      {...props}
    >
      {withHandle ? (
        <div className="z-10 flex h-6 w-4 shrink-0 items-center justify-center rounded-md border border-border bg-card">
          <GripVerticalIcon className="size-3 text-muted-foreground" />
        </div>
      ) : null}
    </Separator>
  )
})
ResizableHandle.displayName = "ResizableHandle"

export { ResizablePanelGroup, ResizablePanel, ResizableHandle }
