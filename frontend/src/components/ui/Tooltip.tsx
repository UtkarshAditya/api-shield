import * as RT from "@radix-ui/react-tooltip";
import type { ReactNode } from "react";

export function Tooltip({ content, children, side = "top" }: { content: ReactNode; children: ReactNode; side?: RT.TooltipContentProps["side"] }) {
  return (
    <RT.Root>
      <RT.Trigger asChild>{children}</RT.Trigger>
      <RT.Portal>
        <RT.Content
          side={side}
          sideOffset={6}
          className="z-50 max-w-xs rounded-lg border border-border bg-surface-2 px-3 py-2 text-xs leading-relaxed text-fg shadow-xl"
        >
          {content}
          <RT.Arrow className="fill-[var(--surface-2)]" />
        </RT.Content>
      </RT.Portal>
    </RT.Root>
  );
}
