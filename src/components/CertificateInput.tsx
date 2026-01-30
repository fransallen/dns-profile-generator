import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Label } from "@/components/ui/label";
import { InfoTooltip } from "@/components/InfoTooltip";
import { Plus, Trash2, ShieldCheck, Upload } from "lucide-react";
import type { CertificateConfig } from "@/lib/profile-generator";

interface CertificateInputProps {
  certificates: CertificateConfig[];
  onChange: (certificates: CertificateConfig[]) => void;
}

export function CertificateInput({ certificates, onChange }: CertificateInputProps) {
  const [isAdding, setIsAdding] = useState(false);
  const [newCertName, setNewCertName] = useState("");
  const [newCertData, setNewCertData] = useState("");
  const [error, setError] = useState("");

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = (event) => {
      const content = event.target?.result as string;
      setNewCertData(content);
      if (!newCertName) {
        setNewCertName(file.name.replace(/\.(pem|cer|crt|der)$/i, ""));
      }
    };
    reader.readAsText(file);
  };

  const validateCertificate = (data: string): boolean => {
    const trimmed = data.trim();
    // Check if it's a valid PEM format or base64 data
    if (trimmed.includes("-----BEGIN CERTIFICATE-----")) {
      return trimmed.includes("-----END CERTIFICATE-----");
    }
    // Check if it's valid base64
    try {
      atob(trimmed.replace(/\s/g, ""));
      return true;
    } catch {
      return false;
    }
  };

  const handleAdd = () => {
    if (!newCertName.trim()) {
      setError("Certificate name is required");
      return;
    }
    if (!newCertData.trim()) {
      setError("Certificate data is required");
      return;
    }
    if (!validateCertificate(newCertData)) {
      setError("Invalid certificate format. Use PEM format or base64 data.");
      return;
    }

    onChange([...certificates, { name: newCertName.trim(), data: newCertData.trim() }]);
    setNewCertName("");
    setNewCertData("");
    setIsAdding(false);
    setError("");
  };

  const handleRemove = (index: number) => {
    onChange(certificates.filter((_, i) => i !== index));
  };

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-2">
        <Label className="text-base font-medium">Certificates</Label>
        <InfoTooltip content="Add root CA or intermediate certificates to trust. Useful for private DNS servers with custom certificates." />
      </div>

      {certificates.length > 0 && (
        <div className="space-y-2">
          {certificates.map((cert, index) => (
            <div
              key={index}
              className="flex items-center justify-between gap-3 rounded-lg border border-border bg-card/50 px-4 py-3"
            >
              <div className="flex items-center gap-3">
                <ShieldCheck className="h-4 w-4 text-primary" />
                <span className="text-sm font-medium">{cert.name}</span>
              </div>
              <Button
                variant="ghost"
                size="sm"
                onClick={() => handleRemove(index)}
                className="h-8 w-8 p-0 text-muted-foreground hover:text-destructive"
              >
                <Trash2 className="h-4 w-4" />
              </Button>
            </div>
          ))}
        </div>
      )}

      {isAdding ? (
        <div className="space-y-4 rounded-lg border border-border bg-muted/30 p-4">
          <div className="space-y-2">
            <Label htmlFor="certName">Certificate Name *</Label>
            <Input
              id="certName"
              value={newCertName}
              onChange={(e) => setNewCertName(e.target.value)}
              placeholder="My Root CA"
            />
          </div>

          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <Label htmlFor="certData">Certificate Data (PEM) *</Label>
              <label className="cursor-pointer">
                <input
                  type="file"
                  accept=".pem,.cer,.crt"
                  onChange={handleFileUpload}
                  className="hidden"
                />
                <span className="inline-flex items-center gap-1.5 text-xs text-primary hover:underline">
                  <Upload className="h-3 w-3" />
                  Upload file
                </span>
              </label>
            </div>
            <Textarea
              id="certData"
              value={newCertData}
              onChange={(e) => setNewCertData(e.target.value)}
              placeholder="-----BEGIN CERTIFICATE-----&#10;MIIDdzCCAl+gAwIBAgI...&#10;-----END CERTIFICATE-----"
              className="min-h-[120px] font-mono text-xs"
            />
          </div>

          {error && <p className="text-xs text-destructive">{error}</p>}

          <div className="flex gap-2">
            <Button onClick={handleAdd} size="sm">
              Add Certificate
            </Button>
            <Button
              variant="ghost"
              size="sm"
              onClick={() => {
                setIsAdding(false);
                setNewCertName("");
                setNewCertData("");
                setError("");
              }}
            >
              Cancel
            </Button>
          </div>
        </div>
      ) : (
        <Button
          variant="outline"
          size="sm"
          onClick={() => setIsAdding(true)}
          className="gap-2"
        >
          <Plus className="h-4 w-4" />
          Add Certificate
        </Button>
      )}
    </div>
  );
}
