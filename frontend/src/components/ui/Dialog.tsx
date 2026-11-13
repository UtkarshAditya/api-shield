import * as D from "@radix-ui/react-dialog";
import { X } from "lucide-react";
import { useState, type ReactNode } from "react";
import { describeError } from "@/lib/errors";
import { cn } from "@/lib/cn";
import { Button } from "./Button";

type ModalProps = {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  title: ReactNode;
  description?: ReactNode;
  children?: ReactNode;
  footer?: ReactNode;
  className?: string;
};

/** Centered dialog. Radix handles focus trapping, Escape and returning focus to the trigger. */
export function Modal({ open, onOpenChange, title, description, children, footer, className }: ModalProps) {
  return (
    <D.Root open={open} onOpenChange={onOpenChange}>
      <D.Portal>
        <D.Overlay className="fixed inset-0 z-40 bg-fg/25 dark:bg-black/55" />
        <D.Content
          className={cn(
            "fixed top-1/2 left-1/2 z-50 max-h-[90vh] w-[calc(100vw-2rem)] max-w-lg -translate-x-1/2 -translate-y-1/2 overflow-y-auto rounded-lg border border-border-strong bg-surface p-5",
            className,
          )}
        >
          <div className="mb-3 flex items-start justify-between gap-4">
            <D.Title className="text-lg font-semibold tracking-tight">{title}</D.Title>
            <D.Close asChild>
              <Button variant="ghost" size="sm" aria-label="Close" className="-mt-1 -mr-2">
                <X className="size-4" aria-hidden />
              </Button>
            </D.Close>
          </div>
          {description ? (
            <D.Description asChild>
              <div className="mb-4 text-sm leading-relaxed text-muted">{description}</div>
            </D.Description>
          ) : (
            <D.Description className="sr-only">{typeof title === "string" ? title : "Dialog"}</D.Description>
          )}
          {children}
          {footer && <div className="mt-5 flex flex-wrap justify-end gap-2">{footer}</div>}
        </D.Content>
      </D.Portal>
    </D.Root>
  );
}

/** Right-hand panel for row details. */
export function Sheet({ open, onOpenChange, title, description, children }: Omit<ModalProps, "footer" | "className">) {
  return (
    <D.Root open={open} onOpenChange={onOpenChange}>
      <D.Portal>
        <D.Overlay className="fixed inset-0 z-40 bg-fg/20 dark:bg-black/50" />
        <D.Content className="fixed top-0 right-0 z-50 h-full w-full max-w-md overflow-y-auto border-l border-border-strong bg-surface p-5">
          <div className="mb-3 flex items-start justify-between gap-4">
            <D.Title className="text-lg font-semibold tracking-tight">{title}</D.Title>
            <D.Close asChild>
              <Button variant="ghost" size="sm" aria-label="Close" className="-mt-1 -mr-2">
                <X className="size-4" aria-hidden />
              </Button>
            </D.Close>
          </div>
          <D.Description className={description ? "mb-4 text-sm text-muted" : "sr-only"}>{description ?? "Details"}</D.Description>
          {children}
        </D.Content>
      </D.Portal>
    </D.Root>
  );
}

type ConfirmProps = {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  title: ReactNode;
  description: ReactNode;
  confirmLabel: string;
  tone?: "danger" | "primary";
  /** May throw; the error is shown in the dialog and the dialog stays open. */
  onConfirm: () => Promise<unknown> | unknown;
  confirmDisabled?: boolean;
  children?: ReactNode;
};

/** Confirmation for consequential actions (ENFORCE, deletes, purges, resets). */
export function ConfirmDialog({ open, onOpenChange, title, description, confirmLabel, tone = "primary", onConfirm, confirmDisabled, children }: ConfirmProps) {
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const change = (next: boolean) => {
    if (pending) return;
    if (!next) setError(null);
    onOpenChange(next);
  };

  const confirm = async () => {
    setPending(true);
    setError(null);
    try {
      await onConfirm();
      onOpenChange(false);
    } catch (err) {
      setError(describeError(err));
    } finally {
      setPending(false);
    }
  };

  return (
    <Modal
      open={open}
      onOpenChange={change}
      title={title}
      description={description}
      footer={
        <>
          <Button variant="secondary" onClick={() => change(false)} disabled={pending}>
            Cancel
          </Button>
          <Button variant={tone} onClick={confirm} disabled={pending || confirmDisabled}>
            {pending ? "Working…" : confirmLabel}
          </Button>
        </>
      }
    >
      {children}
      {error && <InlineError message={error} />}
    </Modal>
  );
}

export function InlineError({ message }: { message: string }) {
  return (
    <p role="alert" className="mt-3 border-l-2 border-signal-mark py-1 pl-3 text-sm text-fg">
      <span>{message}</span>
    </p>
  );
}
