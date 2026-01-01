import { forwardRef } from "react";
import { HelpCircle } from "lucide-react";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip";

interface InfoTooltipProps {
  content: string;
}

export const InfoTooltip = forwardRef<HTMLButtonElement, InfoTooltipProps>(
  function InfoTooltip({ content }, ref) {
    return (
      <Tooltip delayDuration={200}>
        <TooltipTrigger asChild>
          <button
            ref={ref}
            type="button"
            className="inline-flex items-center justify-center rounded-full text-muted-foreground transition-colors hover:text-foreground focus:outline-none focus-visible:ring-2 focus-visible:ring-ring"
            aria-label="More information"
          >
            <HelpCircle className="h-4 w-4" />
          </button>
        </TooltipTrigger>
        <TooltipContent
          side="top"
          className="max-w-xs text-sm"
          sideOffset={5}
        >
          {content}
        </TooltipContent>
      </Tooltip>
    );
  }
);
