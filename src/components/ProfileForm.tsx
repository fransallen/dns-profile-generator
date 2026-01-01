import { useState, useEffect } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Checkbox } from "@/components/ui/checkbox";
import { RadioGroup, RadioGroupCard } from "@/components/ui/radio-group";
import { InfoTooltip } from "@/components/InfoTooltip";
import { ProviderSelector } from "@/components/ProviderSelector";
import { CodePreview } from "@/components/CodePreview";

import { SigningCertificateInput, type SigningCertificates } from "@/components/SigningCertificateInput";
import { dnsProviders, type DNSProvider } from "@/lib/dns-providers";
import {
  generateMobileConfig,
  downloadProfile,
  type ProfileConfig,
  type CertificateConfig,
} from "@/lib/profile-generator";
import { signMobileConfig, downloadSignedProfile } from "@/lib/profile-signer";
import { toast } from "sonner";
import { Sparkles, RefreshCw } from "lucide-react";

export function ProfileForm() {
  const [selectedProvider, setSelectedProvider] = useState<DNSProvider>(dnsProviders[0]);
  const [profileName, setProfileName] = useState("Encrypted DNS");
  const [organizationName, setOrganizationName] = useState("");
  const [profileIdentifier, setProfileIdentifier] = useState("com.example.dns");
  const [dnsProtocol, setDnsProtocol] = useState<"HTTPS" | "TLS">("HTTPS");
  const [serverUrl, setServerUrl] = useState(dnsProviders[0].dohUrl);
  const [serverIps, setServerIps] = useState(dnsProviders[0].ips?.join(", ") || "");
  const [encryptedOnly, setEncryptedOnly] = useState(false);
  const [payloadScope, setPayloadScope] = useState<"System" | "User">("System");
  const [certificates] = useState<CertificateConfig[]>([]);
  const [signingEnabled, setSigningEnabled] = useState(false);
  const [signingCerts, setSigningCerts] = useState<SigningCertificates | null>(null);
  const [generatedXml, setGeneratedXml] = useState<string | null>(null);
  const [signedProfile, setSignedProfile] = useState<Uint8Array | null>(null);
  const [errors, setErrors] = useState<Record<string, string>>({});

  useEffect(() => {
    if (selectedProvider.id !== "custom") {
      setServerUrl(dnsProtocol === "HTTPS" ? selectedProvider.dohUrl : selectedProvider.dotHostname);
      setServerIps(selectedProvider.ips?.join(", ") || "");
    }
  }, [selectedProvider, dnsProtocol]);

  const handleProviderSelect = (provider: DNSProvider) => {
    setSelectedProvider(provider);
    if (provider.id !== "custom") {
      setProfileName(provider.name);
      setProfileIdentifier(`com.${provider.id}.dns`);
      setServerUrl(dnsProtocol === "HTTPS" ? provider.dohUrl : provider.dotHostname);
      setServerIps(provider.ips?.join(", ") || "");
    } else {
      setProfileName("");
      setProfileIdentifier("");
      setServerUrl("");
      setServerIps("");
    }
  };

  const validateForm = (): boolean => {
    const newErrors: Record<string, string> = {};

    if (!profileName.trim()) {
      newErrors.profileName = "Profile name is required";
    }

    if (!profileIdentifier.trim()) {
      newErrors.profileIdentifier = "Profile identifier is required";
    } else if (!/^[a-zA-Z][a-zA-Z0-9.-]*$/.test(profileIdentifier)) {
      newErrors.profileIdentifier = "Invalid identifier format (use reverse-DNS style)";
    }

    if (!serverUrl.trim()) {
      newErrors.serverUrl = "Server URL is required";
    } else if (dnsProtocol === "HTTPS" && !serverUrl.startsWith("https://")) {
      newErrors.serverUrl = "DoH URL must start with https://";
    }

    if (serverIps.trim()) {
      const ips = serverIps.split(",").map((ip) => ip.trim());
      const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
      const ipv6Regex = /^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$/;

      for (const ip of ips) {
        if (ip && !ipv4Regex.test(ip) && !ipv6Regex.test(ip)) {
          newErrors.serverIps = "Invalid IP address format";
          break;
        }
      }
    }

    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const handleGenerate = () => {
    if (!validateForm()) {
      toast.error("Please fix the form errors");
      return;
    }

    if (signingEnabled && !signingCerts) {
      toast.error("Please provide signing certificates or disable signing");
      return;
    }

    const config: ProfileConfig = {
      profileName: profileName.trim(),
      organizationName: organizationName.trim(),
      profileIdentifier: profileIdentifier.trim(),
      dnsProtocol,
      serverUrl: serverUrl.trim(),
      serverIps: serverIps
        .split(",")
        .map((ip) => ip.trim())
        .filter(Boolean),
      encryptedOnly,
      payloadScope,
      certificates,
    };

    const xml = generateMobileConfig(config);
    setGeneratedXml(xml);

    // Sign the profile if signing is enabled
    if (signingEnabled && signingCerts) {
      try {
        const signed = signMobileConfig(xml, signingCerts);
        setSignedProfile(signed);
        toast.success("Profile generated and signed successfully");
      } catch (error) {
        console.error("Signing error:", error);
        toast.error(`Failed to sign profile: ${error instanceof Error ? error.message : "Unknown error"}`);
        setSignedProfile(null);
      }
    } else {
      setSignedProfile(null);
      toast.success("Profile generated successfully");
    }
  };

  const handleDownload = () => {
    const filename = profileName.replace(/[^a-zA-Z0-9-_]/g, "_") || "dns-profile";

    if (signedProfile) {
      downloadSignedProfile(signedProfile, filename);
      toast.success("Signed profile downloaded");
    } else if (generatedXml) {
      downloadProfile(generatedXml, filename);
      toast.success("Profile downloaded");
    }
  };

  const handleReset = () => {
    setSelectedProvider(dnsProviders[0]);
    setProfileName("Encrypted DNS");
    setOrganizationName("");
    setProfileIdentifier("com.example.dns");
    setDnsProtocol("HTTPS");
    setServerUrl(dnsProviders[0].dohUrl);
    setServerIps(dnsProviders[0].ips?.join(", ") || "");
    setEncryptedOnly(false);
    setPayloadScope("System");

    setSigningEnabled(false);
    setSigningCerts(null);
    setGeneratedXml(null);
    setSignedProfile(null);
    setErrors({});
  };

  return (
    <div className="space-y-8">
      {/* Provider Selection */}
      <div className="space-y-3">
        <div className="flex items-center gap-2">
          <Label className="text-base font-medium">DNS Provider</Label>
          <InfoTooltip content="Select a pre-configured DNS provider or choose Custom to enter your own server details." />
        </div>
        <ProviderSelector selectedProvider={selectedProvider.id} onSelect={handleProviderSelect} />
        {selectedProvider.description && selectedProvider.id !== "custom" && (
          <p className="text-sm text-muted-foreground">{selectedProvider.description}</p>
        )}
      </div>

      {/* Profile Details */}
      <div className="grid gap-6 sm:grid-cols-2">
        <div className="space-y-2">
          <div className="flex items-center gap-2">
            <Label htmlFor="profileName">Profile Name *</Label>
            <InfoTooltip content="The name displayed in iOS/macOS Settings when viewing installed profiles." />
          </div>
          <Input
            id="profileName"
            value={profileName}
            onChange={(e) => setProfileName(e.target.value)}
            placeholder="My Encrypted DNS"
            className={errors.profileName ? "border-destructive" : ""}
          />
          {errors.profileName && <p className="text-xs text-destructive">{errors.profileName}</p>}
        </div>

        <div className="space-y-2">
          <div className="flex items-center gap-2">
            <Label htmlFor="organizationName">Organization Name</Label>
            <InfoTooltip content="Optional. Your company or organization name to display in the profile." />
          </div>
          <Input
            id="organizationName"
            value={organizationName}
            onChange={(e) => setOrganizationName(e.target.value)}
            placeholder="My Company"
          />
        </div>

        <div className="space-y-2 sm:col-span-2">
          <div className="flex items-center gap-2">
            <Label htmlFor="profileIdentifier">Profile Identifier *</Label>
            <InfoTooltip content="A unique reverse-DNS style identifier (e.g., com.company.dns). Used internally by Apple to manage profiles." />
          </div>
          <Input
            id="profileIdentifier"
            value={profileIdentifier}
            onChange={(e) => setProfileIdentifier(e.target.value)}
            placeholder="com.example.dns"
            className={errors.profileIdentifier ? "border-destructive" : ""}
          />
          {errors.profileIdentifier && <p className="text-xs text-destructive">{errors.profileIdentifier}</p>}
        </div>
      </div>

      {/* DNS Protocol */}
      <div className="space-y-3">
        <div className="flex items-center gap-2">
          <Label className="text-base font-medium">DNS Protocol</Label>
          <InfoTooltip content="DoH (DNS over HTTPS) uses port 443 and is harder to block. DoT (DNS over TLS) uses port 853 and is a dedicated protocol." />
        </div>
        <RadioGroup
          value={dnsProtocol}
          onValueChange={(value) => setDnsProtocol(value as "HTTPS" | "TLS")}
          className="grid gap-3 sm:grid-cols-2"
        >
          <RadioGroupCard
            value="HTTPS"
            label="DNS over HTTPS (DoH)"
            description="Uses HTTPS on port 443, harder to block"
          />
          <RadioGroupCard
            value="TLS"
            label="DNS over TLS (DoT)"
            description="Uses TLS on port 853, dedicated protocol"
          />
        </RadioGroup>
      </div>

      {/* Server Configuration */}
      <div className="grid gap-6 sm:grid-cols-2">
        <div className="space-y-2">
          <div className="flex items-center gap-2">
            <Label htmlFor="serverUrl">{dnsProtocol === "HTTPS" ? "Server URL *" : "Server Hostname *"}</Label>
            <InfoTooltip
              content={
                dnsProtocol === "HTTPS"
                  ? "The full HTTPS URL for DNS queries (e.g., https://dns.example.com/dns-query)"
                  : "The hostname for the DoT server (e.g., dns.example.com)"
              }
            />
          </div>
          <Input
            id="serverUrl"
            value={serverUrl}
            onChange={(e) => setServerUrl(e.target.value)}
            placeholder={dnsProtocol === "HTTPS" ? "https://dns.example.com/dns-query" : "dns.example.com"}
            className={errors.serverUrl ? "border-destructive" : ""}
          />
          {errors.serverUrl && <p className="text-xs text-destructive">{errors.serverUrl}</p>}
        </div>

        <div className="space-y-2">
          <div className="flex items-center gap-2">
            <Label htmlFor="serverIps">Server IP Addresses</Label>
            <InfoTooltip content="Optional. Comma-separated list of IPv4/IPv6 addresses. Helps with initial connection before DNS resolution." />
          </div>
          <Input
            id="serverIps"
            value={serverIps}
            onChange={(e) => setServerIps(e.target.value)}
            placeholder="1.1.1.1, 1.0.0.1"
            className={errors.serverIps ? "border-destructive" : ""}
          />
          {errors.serverIps && <p className="text-xs text-destructive">{errors.serverIps}</p>}
        </div>
      </div>

      {/* Additional Options */}
      <div className="space-y-4">
        <div className="flex items-center gap-2">
          <Label className="text-base font-medium">Additional Options</Label>
        </div>

        <div className="flex items-center gap-3">
          <Checkbox
            id="encryptedOnly"
            checked={encryptedOnly}
            onCheckedChange={(checked) => setEncryptedOnly(checked === true)}
          />
          <div className="flex items-center gap-2">
            <Label htmlFor="encryptedOnly" className="cursor-pointer font-normal">
              Prohibit disabling encrypted DNS
            </Label>
            <InfoTooltip content="When enabled, users cannot disable the encrypted DNS settings. Use with caution on managed devices." />
          </div>
        </div>

        <div className="space-y-3">
          <div className="flex items-center gap-2">
            <Label>Payload Scope</Label>
            <InfoTooltip content="System scope applies to all users on the device. User scope only applies to the current user." />
          </div>
          <RadioGroup
            value={payloadScope}
            onValueChange={(value) => setPayloadScope(value as "System" | "User")}
            className="flex gap-4"
          >
            <div className="flex items-center gap-2">
              <RadioGroupCard value="System" label="System" className="w-auto px-6" />
            </div>
            <div className="flex items-center gap-2">
              <RadioGroupCard value="User" label="User" className="w-auto px-6" />
            </div>
          </RadioGroup>
        </div>

        {/* Signing Section */}
        <div className="space-y-3">
          <div className="flex items-center gap-2">
            <Label className="text-base font-medium">Profile Signing</Label>
            <InfoTooltip content="Sign the profile with your certificate for verification. Signed profiles show as 'Verified' in iOS/macOS Settings and help establish trust." />
          </div>
          <SigningCertificateInput
            enabled={signingEnabled}
            onEnabledChange={setSigningEnabled}
            certificates={signingCerts}
            onChange={setSigningCerts}
          />
        </div>
      </div>

      {/* Action Buttons */}
      <div className="flex flex-wrap gap-3">
        <Button onClick={handleGenerate} size="lg" className="gap-2">
          <Sparkles className="h-4 w-4" />
          Generate Profile
        </Button>
        <Button onClick={handleReset} variant="outline" size="lg" className="gap-2">
          <RefreshCw className="h-4 w-4" />
          Reset
        </Button>
      </div>

      {/* Generated Preview */}
      {generatedXml && (
        <CodePreview
          code={generatedXml}
          filename={`${profileName.replace(/[^a-zA-Z0-9-_]/g, "_") || "dns-profile"}.mobileconfig`}
          onDownload={handleDownload}
          isSigned={!!signedProfile}
        />
      )}
    </div>
  );
}
