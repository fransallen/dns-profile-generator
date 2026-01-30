import { ProfileForm } from "@/components/ProfileForm";
import { ThemeToggle } from "@/components/ThemeToggle";
import { Shield, Smartphone, Monitor, Tv, Apple } from "lucide-react";
import { Link } from "react-router-dom";

const Index = () => {
  return (
    <div className="min-h-screen bg-background">
      {/* Header */}
      <header className="border-b border-border bg-card/50 backdrop-blur-sm">
        <div className="container mx-auto flex items-center justify-between px-4 py-4">
          <Link to="/" className="flex items-center gap-2">
            <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-primary">
              <Shield className="h-5 w-5 text-primary-foreground" />
            </div>
            <span className="text-lg font-semibold">DNS Profile Generator</span>
          </Link>
          <div className="flex items-center gap-2">
            <ThemeToggle />
            <a
              href="https://github.com/fransallen/dns-profile-generator"
              target="_blank"
              rel="noopener noreferrer"
              className="flex gap-2 text-sm text-muted-foreground transition-colors hover:text-foreground"
            >
              <svg className="h-4 w-4" viewBox="0 0 24 24" fill="currentColor">
                <path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z" />
              </svg>
              GitHub
            </a>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="container mx-auto px-4 py-8 md:py-12">
        <div className="mx-auto max-w-3xl">
          {/* Hero Section */}
          <div className="mb-10 animate-slide-in text-center">
            <h1 className="mb-4 text-3xl font-bold tracking-tight md:text-4xl">
              Apple Encrypted DNS
              <br />
              <span className="text-primary">Profile Generator</span>
            </h1>
            <p className="mx-auto max-w-lg text-muted-foreground">
              Create configuration profiles for DNS over HTTPS (DoH) or DNS over
              TLS (DoT) to enable encrypted DNS system-wide on your Apple
              devices.
            </p>
          </div>

          {/* Form Card */}
          <div className="animate-fade-in rounded-2xl border border-border bg-card p-6 shadow-card md:p-8">
            <ProfileForm />
          </div>

          {/* Installation Instructions */}
          <div className="mt-8 animate-fade-in space-y-6">
            <h2 className="text-xl font-semibold">Installation Instructions</h2>

            <div className="grid gap-6 md:grid-cols-2">
              {/* iOS / iPadOS */}
              <div className="rounded-xl border border-border bg-card p-5">
                <h3 className="mb-4 flex items-center gap-2 font-medium">
                  <Smartphone className="h-4 w-4 text-primary" />
                  iOS / iPadOS
                </h3>
                <ol className="space-y-2 text-sm text-muted-foreground">
                  <li className="flex gap-2">
                    <span className="font-medium text-foreground">1.</span>
                    Download the configuration profile.
                  </li>
                  <li className="flex gap-2">
                    <span className="font-medium text-foreground">2.</span>
                    Open the Settings app.
                  </li>
                  <li className="flex gap-2">
                    <span className="font-medium text-foreground">3.</span>
                    Tap Profile Downloaded.
                  </li>
                  <li className="flex gap-2">
                    <span className="font-medium text-foreground">4.</span>
                    Tap Install in the upper-right corner, and follow the
                    onscreen instructions.
                  </li>
                </ol>
              </div>

              {/* macOS */}
              <div className="rounded-xl border border-border bg-card p-5">
                <h3 className="mb-4 flex items-center gap-2 font-medium">
                  <Monitor className="h-4 w-4 text-primary" />
                  macOS
                </h3>
                <ol className="space-y-2 text-sm text-muted-foreground">
                  <li className="flex gap-2">
                    <span className="font-medium text-foreground">1.</span>
                    Download the configuration profile.
                  </li>
                  <li className="flex gap-2">
                    <span className="font-medium text-foreground">2.</span>
                    Open the downloaded .mobileconfig file.
                  </li>
                  <li className="flex gap-2">
                    <span className="font-medium text-foreground">3.</span>
                    Open System Preferences.
                  </li>
                  <li className="flex gap-2">
                    <span className="font-medium text-foreground">4.</span>
                    Go to Profiles.
                  </li>
                  <li className="flex gap-2">
                    <span className="font-medium text-foreground">5.</span>
                    Click Install.
                  </li>
                </ol>
              </div>

              {/* tvOS */}
              <div className="rounded-xl border border-border bg-card p-5 md:col-span-2">
                <h3 className="mb-4 flex items-center gap-2 font-medium">
                  <Tv className="h-4 w-4 text-primary" />
                  tvOS
                </h3>
                <ol className="space-y-2 text-sm text-muted-foreground">
                  <li className="flex gap-2">
                    <span className="font-medium text-foreground">1.</span>
                    Open the Settings app.
                  </li>
                  <li className="flex gap-2">
                    <span className="font-medium text-foreground">2.</span>
                    Go to General → Privacy.
                  </li>
                  <li className="flex gap-2">
                    <span className="font-medium text-foreground">3.</span>
                    Hover over Share Apple TV Analytics without pressing.
                  </li>
                  <li className="flex gap-2">
                    <span className="font-medium text-foreground">4.</span>
                    Press Play on the remote.
                  </li>
                  <li className="flex gap-2">
                    <span className="font-medium text-foreground">5.</span>
                    Select Add Profile.
                  </li>
                  <li className="flex gap-2">
                    <span className="font-medium text-foreground">6.</span>
                    Enter the generated short link.
                  </li>
                  <li className="flex gap-2">
                    <span className="font-medium text-foreground">7.</span>
                    Install the profile following the onscreen instructions.
                  </li>
                </ol>
              </div>
            </div>
          </div>

          {/* Compatibility Note */}
          <div className="mt-8 animate-fade-in rounded-xl bg-secondary/50 p-6">
            <h3 className="mb-3 flex items-center gap-2 font-medium">
              <Apple className="h-4 w-4" />
              Compatibility
            </h3>
            <div className="grid gap-2 text-sm text-muted-foreground">
              <p>
                <span className="font-medium text-foreground">
                  iOS / iPadOS:
                </span>{" "}
                14.0 and later
              </p>
              <p>
                <span className="font-medium text-foreground">macOS:</span> 11.0
                (Big Sur) and later
              </p>
              <p>
                <span className="font-medium text-foreground">tvOS:</span> 14.0
                and later
              </p>
            </div>
          </div>

          {/* Learn More */}
          <div className="mt-8 animate-fade-in rounded-xl border border-border bg-card p-6">
            <h2 className="mb-4 text-xl font-semibold">Learn More</h2>
            <div className="space-y-4 text-sm text-muted-foreground">
              <p>
                Apple's encrypted DNS support allows you to configure DNS over
                HTTPS (DoH) or DNS over TLS (DoT) system-wide on your devices.
                This ensures that your DNS queries are encrypted and protected
                from eavesdropping, providing enhanced privacy and security.
              </p>
              <p>
                Configuration profiles (.mobileconfig files) are the official
                way to deploy encrypted DNS settings across Apple devices. Once
                installed, the DNS settings apply to all network connections,
                including Wi-Fi and cellular.
              </p>
              <a
                href="https://developer.apple.com/documentation/devicemanagement/dnssettings"
                target="_blank"
                rel="noopener noreferrer"
                className="inline-flex items-center gap-1 text-primary hover:underline"
              >
                Read the Apple DNS Settings Documentation →
              </a>
            </div>
          </div>
        </div>
      </main>

      {/* Footer */}
      <footer className="border-t border-border py-6">
        <div className="container mx-auto px-4 text-center text-sm text-muted-foreground">
          <p className="mb-2">
            No data is collected or stored. All profile generation happens
            locally in your browser.
          </p>
          <p>
            Made by{" "}
            <a
              href="https://upset.dev"
              target="_blank"
              rel="noopener noreferrer"
              className="text-primary hover:underline"
            >
              upset.dev
            </a>
          </p>
        </div>
      </footer>
    </div>
  );
};

export default Index;
