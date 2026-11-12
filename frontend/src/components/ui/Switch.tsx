import * as S from "@radix-ui/react-switch";
import { cn } from "@/lib/cn";

type Props = {
  checked: boolean;
  onCheckedChange: (v: boolean) => void;
  /** Accessible name; required because the switch is often shown without visible text. */
  label: string;
  disabled?: boolean;
  id?: string;
};

export function Switch({ checked, onCheckedChange, label, disabled, id }: Props) {
  return (
    <S.Root
      id={id}
      checked={checked}
      onCheckedChange={onCheckedChange}
      disabled={disabled}
      aria-label={label}
      className={cn(
        "relative inline-flex h-5 w-9 shrink-0 items-center rounded-full border border-border transition-colors disabled:cursor-not-allowed disabled:opacity-50",
        checked ? "bg-accent" : "bg-surface-2",
      )}
    >
      <S.Thumb
        className={cn(
          "block size-4 rounded-full bg-surface shadow transition-transform",
          checked ? "translate-x-[17px]" : "translate-x-[1px]",
        )}
      />
    </S.Root>
  );
}
