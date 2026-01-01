import { useState, useCallback } from "react";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { InfoTooltip } from "@/components/InfoTooltip";
import { Checkbox } from "@/components/ui/checkbox";
import {
  validatePemCertificate,
  validatePemPrivateKey,
  getCertificateInfo,
  parseCertificateChain,
} from "@/lib/profile-signer";
import {
  Shield,
  Upload,
  CheckCircle2,
  XCircle,
  ChevronDown,
  ChevronUp,
} from "lucide-react";

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

export function SigningCertificateInput({
  enabled,
  onEnabledChange,
  certificates,
  onChange,
}: SigningCertificateInputProps) {
  const [isExpanded, setIsExpanded] = useState(false);
  const [signingCert, setSigningCert] = useState("");
  const [privateKey, setPrivateKey] = useState("");
  const [chainCerts, setChainCerts] = useState("");
  const [errors, setErrors] = useState<Record<string, string>>({});

  const handleFileUpload = useCallback(
    (
      field: "signingCert" | "privateKey" | "chainCerts",
      e: React.ChangeEvent<HTMLInputElement>
    ) => {
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
    [signingCert, privateKey, chainCerts]
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
    [onChange]
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
    [signingCert, privateKey, chainCerts, validateAndUpdate]
  );

  const handleEnabledChange = (checked: boolean) => {
    onEnabledChange(checked);
    if (!checked) {
      onChange(null);
    } else if (signingCert && privateKey) {
      validateAndUpdate(signingCert, privateKey, chainCerts);
    }
  };

  const certInfo = signingCert ? getCertificateInfo(signingCert) : null;
  const isValid = enabled && certificates !== null;

  return (
    <div className="space-y-4 rounded-lg border border-border bg-card p-4">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Checkbox
            id="enableSigning"
            checked={enabled}
            onCheckedChange={handleEnabledChange}
          />
          <div className="flex items-center gap-2">
            <Shield className="h-4 w-4 text-primary" />
            <Label htmlFor="enableSigning" className="cursor-pointer font-medium">
              Sign Profile with S/MIME
            </Label>
            <InfoTooltip content="Sign the profile with your certificate for verification. Signed profiles show as 'Verified' in iOS/macOS Settings." />
          </div>
        </div>
        {enabled && (
          <div className="flex items-center gap-2">
            {isValid ? (
              <span className="flex items-center gap-1 text-sm text-green-600">
                <CheckCircle2 className="h-4 w-4" />
                Ready
              </span>
            ) : (
              <span className="flex items-center gap-1 text-sm text-muted-foreground">
                <XCircle className="h-4 w-4" />
                Incomplete
              </span>
            )}
            <Button
              variant="ghost"
              size="sm"
              onClick={() => setIsExpanded(!isExpanded)}
            >
              {isExpanded ? (
                <ChevronUp className="h-4 w-4" />
              ) : (
                <ChevronDown className="h-4 w-4" />
              )}
            </Button>
          </div>
        )}
      </div>

      {enabled && isExpanded && (
        <div className="space-y-4 pt-2">
          {/* Signing Certificate */}
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Label>Signing Certificate *</Label>
                <InfoTooltip content="Your signing certificate in PEM format (.crt, .pem file)" />
              </div>
              <label className="cursor-pointer">
                <input
                  type="file"
                  accept=".pem,.crt,.cer"
                  className="hidden"
                  onChange={(e) => handleFileUpload("signingCert", e)}
                />
                <Button variant="outline" size="sm" className="gap-1" asChild>
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
              rows={4}
            />
            {errors.signingCert && (
              <p className="text-xs text-destructive">{errors.signingCert}</p>
            )}
            {certInfo && (
              <div className="rounded bg-muted/50 px-3 py-2 text-xs text-muted-foreground">
                <p>
                  <strong>Subject:</strong> {certInfo.subject}
                </p>
                <p>
                  <strong>Issuer:</strong> {certInfo.issuer}
                </p>
                <p>
                  <strong>Valid:</strong> {certInfo.validFrom.toLocaleDateString()}{" "}
                  - {certInfo.validTo.toLocaleDateString()}
                </p>
              </div>
            )}
          </div>

          {/* Private Key */}
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Label>Private Key *</Label>
                <InfoTooltip content="The private key for your signing certificate in PEM format (.key, .pem file)" />
              </div>
              <label className="cursor-pointer">
                <input
                  type="file"
                  accept=".pem,.key"
                  className="hidden"
                  onChange={(e) => handleFileUpload("privateKey", e)}
                />
                <Button variant="outline" size="sm" className="gap-1" asChild>
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
              rows={4}
            />
            {errors.privateKey && (
              <p className="text-xs text-destructive">{errors.privateKey}</p>
            )}
          </div>

          {/* Certificate Chain */}
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Label>Certificate Chain</Label>
                <InfoTooltip content="Optional. Intermediate certificates in PEM format. Multiple certificates can be concatenated." />
              </div>
              <label className="cursor-pointer">
                <input
                  type="file"
                  accept=".pem,.crt,.cer"
                  className="hidden"
                  onChange={(e) => handleFileUpload("chainCerts", e)}
                />
                <Button variant="outline" size="sm" className="gap-1" asChild>
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
              rows={3}
            />
            {errors.chainCerts && (
              <p className="text-xs text-destructive">{errors.chainCerts}</p>
            )}
            {chainCerts && !errors.chainCerts && (
              <p className="text-xs text-muted-foreground">
                Found {parseCertificateChain(chainCerts).length} certificate(s) in
                chain
              </p>
            )}
          </div>

          <p className="text-xs text-muted-foreground">
            ⚠️ Private keys are processed entirely in your browser and never sent
            to any server.
          </p>
        </div>
      )}

      {enabled && !isExpanded && isValid && certInfo && (
        <p className="text-xs text-muted-foreground">
          Signing with: {certInfo.subject} (issued by {certInfo.issuer})
        </p>
      )}
    </div>
  );
}
