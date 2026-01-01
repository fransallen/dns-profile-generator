import { useState, useCallback, useEffect, forwardRef } from "react";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { InfoTooltip } from "@/components/InfoTooltip";
import { Switch } from "@/components/ui/switch";
import {
  validatePemCertificate,
  validatePemPrivateKey,
  getCertificateInfo,
  parseCertificateChain,
} from "@/lib/profile-signer";
import { Shield, Upload, CheckCircle2, AlertCircle } from "lucide-react";
import {
  Collapsible,
  CollapsibleContent,
  CollapsibleTrigger,
} from "@/components/ui/collapsible";

export interface SigningCertificates {
  signingCert: string;
  privateKey: string;
  chainCerts: string[];
}

interface SigningCertificateInputProps {
  enabled: boolean;
  onEnabledChange: (enabled: boolean) => void;
  certificates: SigningCertificates | null;
  onChange: (certificates: SigningCertificates | null) => void;
}

export const SigningCertificateInput = forwardRef<HTMLDivElement, SigningCertificateInputProps>(
  function SigningCertificateInput({ enabled, onEnabledChange, certificates, onChange }, ref) {
    const [isExpanded, setIsExpanded] = useState(false);
    const [signingCert, setSigningCert] = useState("");
    const [privateKey, setPrivateKey] = useState("");
    const [chainCerts, setChainCerts] = useState("");
    const [errors, setErrors] = useState<Record<string, string>>({});

    // Auto-expand when enabled and not yet configured
    useEffect(() => {
      if (enabled && !certificates) {
        setIsExpanded(true);
      }
    }, [enabled, certificates]);

    const handleFileUpload = useCallback(
      (field: "signingCert" | "privateKey" | "chainCerts", e: React.ChangeEvent<HTMLInputElement>) => {
        const file = e.target.files?.[0];
        if (!file) return;

        const reader = new FileReader();
        reader.onload = (event) => {
          const content = event.target?.result as string;
          if (field === "signingCert") {
            setSigningCert(content);
            validateAndUpdate(content, privateKey, chainCerts);
          } else if (field === "privateKey") {
            setPrivateKey(content);
            validateAndUpdate(signingCert, content, chainCerts);
          } else {
            setChainCerts(content);
            validateAndUpdate(signingCert, privateKey, content);
          }
        };
        reader.readAsText(file);
      },
      [signingCert, privateKey, chainCerts],
    );

    const validateAndUpdate = useCallback(
      (cert: string, key: string, chain: string) => {
        const newErrors: Record<string, string> = {};

        if (cert && !validatePemCertificate(cert)) {
          newErrors.signingCert = "Invalid PEM certificate";
        }

        if (key && !validatePemPrivateKey(key)) {
          newErrors.privateKey = "Invalid PEM private key";
        }

        const chainCertsParsed = chain ? parseCertificateChain(chain) : [];
        if (chain && chainCertsParsed.length === 0) {
          newErrors.chainCerts = "No valid certificates found in chain";
        }

        setErrors(newErrors);

        if (
          cert &&
          key &&
          Object.keys(newErrors).length === 0 &&
          validatePemCertificate(cert) &&
          validatePemPrivateKey(key)
        ) {
          onChange({
            signingCert: cert,
            privateKey: key,
            chainCerts: chainCertsParsed,
          });
        } else {
          onChange(null);
        }
      },
      [onChange],
    );

    const handleTextChange = useCallback(
      (field: "signingCert" | "privateKey" | "chainCerts", value: string) => {
        if (field === "signingCert") {
          setSigningCert(value);
          validateAndUpdate(value, privateKey, chainCerts);
        } else if (field === "privateKey") {
          setPrivateKey(value);
          validateAndUpdate(signingCert, value, chainCerts);
        } else {
          setChainCerts(value);
          validateAndUpdate(signingCert, privateKey, value);
        }
      },
      [signingCert, privateKey, chainCerts, validateAndUpdate],
    );

    const handleEnabledChange = (checked: boolean) => {
      onEnabledChange(checked);
      if (!checked) {
        onChange(null);
        setIsExpanded(false);
      } else if (signingCert && privateKey) {
        validateAndUpdate(signingCert, privateKey, chainCerts);
      }
    };

    const certInfo = signingCert ? getCertificateInfo(signingCert) : null;
    const isValid = enabled && certificates !== null;

    return (
      <div
        ref={ref}
        className={`rounded-lg border transition-all duration-200 ${
          enabled
            ? isValid
              ? "border-green-500/50 bg-green-500/5"
              : "border-primary/50 bg-primary/5"
            : "border-border bg-card"
        }`}
      >
        <Collapsible open={enabled && isExpanded} onOpenChange={setIsExpanded}>
          <div className="flex items-center justify-between p-4">
            <div className="flex items-center gap-3">
              <Shield className={`h-5 w-5 ${enabled ? (isValid ? "text-green-500" : "text-primary") : "text-muted-foreground"}`} />
              <div className="flex flex-col">
                <Label htmlFor="enableSigning" className="cursor-pointer font-medium">
                  Sign with S/MIME
                </Label>
                {enabled && isValid && certInfo && !isExpanded && (
                  <span className="text-xs text-muted-foreground">
                    {certInfo.subject}
                  </span>
                )}
              </div>
            </div>
            <div className="flex items-center gap-3">
              {enabled && (
                <CollapsibleTrigger asChild>
                  <Button
                    variant="ghost"
                    size="sm"
                    className="h-8 px-2 text-xs text-muted-foreground hover:text-foreground"
                  >
                    {isExpanded ? "Hide" : "Configure"}
                  </Button>
                </CollapsibleTrigger>
              )}
              {enabled && (
                <div className="flex items-center gap-1.5">
                  {isValid ? (
                    <CheckCircle2 className="h-4 w-4 text-green-500" />
                  ) : (
                    <AlertCircle className="h-4 w-4 text-amber-500" />
                  )}
                  <span className={`text-xs font-medium ${isValid ? "text-green-600" : "text-amber-600"}`}>
                    {isValid ? "Ready" : "Setup required"}
                  </span>
                </div>
              )}
              <Switch
                id="enableSigning"
                checked={enabled}
                onCheckedChange={handleEnabledChange}
              />
            </div>
          </div>

          <CollapsibleContent className="overflow-hidden data-[state=closed]:animate-accordion-up data-[state=open]:animate-accordion-down">
            <div className="space-y-4 border-t border-border/50 p-4">
              {/* Signing Certificate */}
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <Label className="text-sm">Signing Certificate *</Label>
                    <InfoTooltip content="Your signing certificate in PEM format (.crt, .pem file)" />
                  </div>
                  <label className="cursor-pointer">
                    <input
                      type="file"
                      accept=".pem,.crt,.cer"
                      className="hidden"
                      onChange={(e) => handleFileUpload("signingCert", e)}
                    />
                    <Button variant="outline" size="sm" className="h-7 gap-1.5 text-xs" asChild>
                      <span>
                        <Upload className="h-3 w-3" />
                        Upload
                      </span>
                    </Button>
                  </label>
                </div>
                <Textarea
                  value={signingCert}
                  onChange={(e) => handleTextChange("signingCert", e.target.value)}
                  placeholder="-----BEGIN CERTIFICATE-----&#10;...&#10;-----END CERTIFICATE-----"
                  className={`font-mono text-xs ${errors.signingCert ? "border-destructive" : ""}`}
                  rows={3}
                />
                {errors.signingCert && <p className="text-xs text-destructive">{errors.signingCert}</p>}
                {certInfo && (
                  <div className="rounded-md bg-muted/50 px-3 py-2 text-xs">
                    <div className="grid gap-1 text-muted-foreground">
                      <p><span className="font-medium text-foreground">Subject:</span> {certInfo.subject}</p>
                      <p><span className="font-medium text-foreground">Issuer:</span> {certInfo.issuer}</p>
                      <p><span className="font-medium text-foreground">Valid:</span> {certInfo.validFrom.toLocaleDateString()} — {certInfo.validTo.toLocaleDateString()}</p>
                    </div>
                  </div>
                )}
              </div>

              {/* Private Key */}
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <Label className="text-sm">Private Key *</Label>
                    <InfoTooltip content="The private key for your signing certificate in PEM format (.key, .pem file)" />
                  </div>
                  <label className="cursor-pointer">
                    <input
                      type="file"
                      accept=".pem,.key"
                      className="hidden"
                      onChange={(e) => handleFileUpload("privateKey", e)}
                    />
                    <Button variant="outline" size="sm" className="h-7 gap-1.5 text-xs" asChild>
                      <span>
                        <Upload className="h-3 w-3" />
                        Upload
                      </span>
                    </Button>
                  </label>
                </div>
                <Textarea
                  value={privateKey}
                  onChange={(e) => handleTextChange("privateKey", e.target.value)}
                  placeholder="-----BEGIN PRIVATE KEY-----&#10;...&#10;-----END PRIVATE KEY-----"
                  className={`font-mono text-xs ${errors.privateKey ? "border-destructive" : ""}`}
                  rows={3}
                />
                {errors.privateKey && <p className="text-xs text-destructive">{errors.privateKey}</p>}
              </div>

              {/* Certificate Chain */}
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <Label className="text-sm">Certificate Chain</Label>
                    <InfoTooltip content="Optional. Intermediate certificates in PEM format. Multiple certificates can be concatenated." />
                  </div>
                  <label className="cursor-pointer">
                    <input
                      type="file"
                      accept=".pem,.crt,.cer"
                      className="hidden"
                      onChange={(e) => handleFileUpload("chainCerts", e)}
                    />
                    <Button variant="outline" size="sm" className="h-7 gap-1.5 text-xs" asChild>
                      <span>
                        <Upload className="h-3 w-3" />
                        Upload
                      </span>
                    </Button>
                  </label>
                </div>
                <Textarea
                  value={chainCerts}
                  onChange={(e) => handleTextChange("chainCerts", e.target.value)}
                  placeholder="-----BEGIN CERTIFICATE-----&#10;...&#10;-----END CERTIFICATE-----"
                  className={`font-mono text-xs ${errors.chainCerts ? "border-destructive" : ""}`}
                  rows={2}
                />
                {errors.chainCerts && <p className="text-xs text-destructive">{errors.chainCerts}</p>}
                {chainCerts && !errors.chainCerts && (
                  <p className="text-xs text-muted-foreground">
                    Found {parseCertificateChain(chainCerts).length} certificate(s) in chain
                  </p>
                )}
              </div>

              <p className="flex items-center gap-1.5 rounded-md bg-muted/50 px-3 py-2 text-xs text-muted-foreground">
                <Shield className="h-3.5 w-3.5 shrink-0" />
                Private keys are processed entirely in your browser and never sent to any server.
              </p>
            </div>
          </CollapsibleContent>
        </Collapsible>
      </div>
    );
  }
);
