import { dnsProviders, type DNSProvider } from "@/lib/dns-providers";
import { cn } from "@/lib/utils";
import { Settings } from "lucide-react";

interface ProviderSelectorProps {
  selectedProvider: string;
  onSelect: (provider: DNSProvider) => void;
}

const providerIcons: Record<string, string> = {
  cloudflare: "/cloudflare-icon.svg",
  google: "/google-icon.svg",
  quad9: "/quad9-icon.svg",
  adguard: "/adguard-icon.svg",
};

export function ProviderSelector({
  selectedProvider,
  onSelect,
}: ProviderSelectorProps) {
  return (
    <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-5">
      {dnsProviders.map((provider) => (
        <button
          key={provider.id}
          type="button"
          onClick={() => onSelect(provider)}
          className={cn(
            "group relative flex flex-col items-center gap-2 rounded-xl border-2 p-4 text-center transition-all hover:border-primary/50 hover:shadow-subtle focus:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2",
            selectedProvider === provider.id
              ? "border-primary bg-accent shadow-subtle"
              : "border-border bg-card"
          )}
        >
          <div
            className={cn(
              "flex h-10 w-10 items-center justify-center rounded-lg transition-colors",
              selectedProvider === provider.id
                ? "text-primary"
                : "text-secondary-foreground group-hover:text-primary"
            )}
          >
            {provider.id === "custom" ? (
              <Settings className="h-5 w-5" />
            ) : (
              <img
                src={providerIcons[provider.id]}
                alt={`${provider.name} icon`}
                className="h-6 w-6"
              />
            )}
          </div>
          <span className="text-sm font-medium">{provider.name}</span>
        </button>
      ))}
    </div>
  );
}
