import * as React from "react";
import * as RadioGroupPrimitive from "@radix-ui/react-radio-group";
import { Circle } from "lucide-react";

import { cn } from "@/lib/utils";

const RadioGroup = React.forwardRef<
  React.ElementRef<typeof RadioGroupPrimitive.Root>,
  React.ComponentPropsWithoutRef<typeof RadioGroupPrimitive.Root>
>(({ className, ...props }, ref) => {
  return <RadioGroupPrimitive.Root className={cn("grid gap-2", className)} {...props} ref={ref} />;
});
RadioGroup.displayName = RadioGroupPrimitive.Root.displayName;

const RadioGroupItem = React.forwardRef<
  React.ElementRef<typeof RadioGroupPrimitive.Item>,
  React.ComponentPropsWithoutRef<typeof RadioGroupPrimitive.Item>
>(({ className, ...props }, ref) => {
  return (
    <RadioGroupPrimitive.Item
      ref={ref}
      className={cn(
        "aspect-square h-4 w-4 rounded-full border border-primary text-primary ring-offset-background focus:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50",
        className,
      )}
      {...props}
    >
      <RadioGroupPrimitive.Indicator className="flex items-center justify-center">
        <Circle className="h-2.5 w-2.5 fill-current text-current" />
      </RadioGroupPrimitive.Indicator>
    </RadioGroupPrimitive.Item>
  );
});
RadioGroupItem.displayName = RadioGroupPrimitive.Item.displayName;

// Card-style radio for visual selection
const RadioGroupCard = React.forwardRef<
  React.ElementRef<typeof RadioGroupPrimitive.Item>,
  React.ComponentPropsWithoutRef<typeof RadioGroupPrimitive.Item> & {
    label: string;
    description?: string;
  }
>(({ className, label, description, ...props }, ref) => {
  return (
    <RadioGroupPrimitive.Item
      ref={ref}
      className={cn(
        "relative flex cursor-pointer rounded-lg border-2 border-border bg-card p-4 transition-all hover:border-primary/50 focus:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 data-[state=checked]:border-primary data-[state=checked]:bg-accent disabled:cursor-not-allowed disabled:opacity-50",
        className
      )}
      {...props}
    >
      <div className="flex w-full items-center gap-3">
        <div className="flex h-5 w-5 shrink-0 items-center justify-center rounded-full border-2 border-current">
          <RadioGroupPrimitive.Indicator>
            <Circle className="h-2.5 w-2.5 fill-primary text-primary" />
          </RadioGroupPrimitive.Indicator>
        </div>
        <div className="flex-1 text-left">
          <div className="text-sm font-medium leading-none">{label}</div>
          {description && (
            <p className="mt-1 text-xs text-muted-foreground">{description}</p>
          )}
        </div>
      </div>
    </RadioGroupPrimitive.Item>
  );
});
RadioGroupCard.displayName = "RadioGroupCard";

export { RadioGroup, RadioGroupItem, RadioGroupCard };
