import * as RT from "@radix-ui/react-tooltip";
import type { ReactNode } from "react";

/** Ink tooltip. Radix shows it on hover and on keyboard focus of the trigger. */
export function Tooltip({ content, children, side = "top" }: { content: ReactNode; children: ReactNode; side?: RT.TooltipContentProps["side"] }) {
  return (
    <RT.Root>
      <RT.Trigger asChild>{children}</RT.Trigger>
      <RT.Portal>
        <RT.Content
          side={side}
          sideOffset={6}
          collisionPadding={8}
          className="z-50 max-w-xs rounded-sm bg-fg px-2.5 py-1.5 text-xs leading-relaxed text-bg"
        >
          {content}
        </RT.Content>
      </RT.Portal>
    </RT.Root>
  );
}
