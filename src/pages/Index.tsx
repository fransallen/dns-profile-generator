import { ProfileForm } from "@/components/ProfileForm";
import { Shield, Smartphone, Monitor, Tv, Apple, Github } from "lucide-react";

const Index = () => {
  return (
    <div className="min-h-screen bg-background">
      {/* Header */}
      <header className="border-b border-border bg-card/50 backdrop-blur-sm">
        <div className="container mx-auto flex items-center justify-between px-4 py-4">
          <div className="flex items-center gap-2">
            <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-primary">
              <Shield className="h-5 w-5 text-primary-foreground" />
            </div>
            <span className="text-lg font-semibold">DNS Profile Generator</span>
          </div>
          <a
            href="https://github.com/fransallen/apple-dns"
            target="_blank"
            rel="noopener noreferrer"
            className="flex items-center gap-2 text-sm text-muted-foreground transition-colors hover:text-foreground"
          >
            <Github className="h-4 w-4" />
            GitHub
          </a>
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
              Create configuration profiles for DNS over HTTPS (DoH) or DNS over TLS (DoT) 
              to enable encrypted DNS system-wide on your Apple devices.
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
                    Tap Install in the upper-right corner, and follow the onscreen instructions.
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
                <span className="font-medium text-foreground">iOS / iPadOS:</span>{" "}
                14.0 and later
              </p>
              <p>
                <span className="font-medium text-foreground">macOS:</span>{" "}
                11.0 (Big Sur) and later
              </p>
              <p>
                <span className="font-medium text-foreground">tvOS:</span>{" "}
                14.0 and later
              </p>
            </div>
          </div>
        </div>
      </main>

      {/* Footer */}
      <footer className="border-t border-border py-6">
        <div className="container mx-auto px-4 text-center text-sm text-muted-foreground">
          <p className="mb-2">
            No data is collected or stored. All profile generation happens locally in your browser.
          </p>
          <p>
            <a
              href="https://developer.apple.com/documentation/devicemanagement/dnssettings"
              target="_blank"
              rel="noopener noreferrer"
              className="text-primary hover:underline"
            >
              Apple DNS Settings Documentation →
            </a>
          </p>
        </div>
      </footer>
    </div>
  );
};

export default Index;
