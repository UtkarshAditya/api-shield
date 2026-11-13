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

/** Square-ish ink switch: on = ink track, off = hairline track. */
export function Switch({ checked, onCheckedChange, label, disabled, id }: Props) {
  return (
    <S.Root
      id={id}
      checked={checked}
      onCheckedChange={onCheckedChange}
      disabled={disabled}
      aria-label={label}
      className={cn(
        "relative inline-flex h-[18px] w-8 shrink-0 items-center rounded-sm border transition-colors ease-ui disabled:cursor-not-allowed disabled:opacity-45",
        checked ? "border-accent bg-accent" : "border-border-strong bg-transparent",
      )}
    >
      <S.Thumb
        className={cn(
          "block size-3 rounded-[1px] transition-transform ease-ui",
          checked ? "translate-x-[15px] bg-accent-fg" : "translate-x-[2px] bg-border-strong",
        )}
      />
    </S.Root>
  );
}
