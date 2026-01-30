// Re-export from pkijs-based signer for signing functionality
export { signMobileConfig, downloadSignedProfile } from "./profile-signer-pkijs";
export type { SigningConfig } from "./profile-signer-pkijs";

import * as pkijs from "pkijs";
import { Convert } from "pvtsutils";

/**
 * Decode PEM to ArrayBuffer
 */
function pemToArrayBuffer(pem: string): ArrayBuffer {
  const b64 = pem
    .replace(/-----BEGIN [^-]+-----/g, "")
    .replace(/-----END [^-]+-----/g, "")
    .replace(/\s/g, "");
  
  return Convert.FromBase64(b64);
}

/**
 * Extracts the first certificate from PEM content (handles fullchain files)
 */
export function extractFirstCertificate(pem: string): string | null {
  const match = pem.match(
    /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/
  );
  return match ? match[0] : null;
}

export type PemValidationResult =
  | { valid: true }
  | {
      valid: false;
      code?: "NO_PEM_BLOCK" | "UNSUPPORTED_KEY_TYPE" | "ENCRYPTED_KEY" | "INVALID_PEM";
      error: string;
    };

/**
 * Validates a PEM certificate (supports fullchain - uses first cert)
 * Supports both RSA and ECDSA certificates via pkijs
 */
export function validatePemCertificate(pem: string): PemValidationResult {
  try {
    // Normalize line endings and trim
    const normalized = pem.replace(/\r\n/g, "\n").trim();
    
    const firstCert = extractFirstCertificate(normalized);
    if (!firstCert) {
      return { valid: false, code: "NO_PEM_BLOCK", error: "No PEM certificate block found" };
    }

    const certBuffer = pemToArrayBuffer(firstCert);
    
    if (certBuffer.byteLength === 0) {
      return { valid: false, code: "INVALID_PEM", error: "Certificate appears to be empty" };
    }
    
    // This will throw if the certificate is invalid
    const cert = pkijs.Certificate.fromBER(certBuffer);
    
    // Verify we got a valid certificate object
    if (!cert.subject || !cert.issuer) {
      return { valid: false, code: "INVALID_PEM", error: "Certificate structure is invalid" };
    }
    
    return { valid: true };
  } catch (err) {
    console.warn("Certificate validation error:", err);
    const errorMessage = err instanceof Error ? err.message : "Unknown error";
    
    // Provide more specific error messages
    if (errorMessage.includes("Object's schema was not verified")) {
      return { valid: false, code: "INVALID_PEM", error: "Certificate format is invalid or corrupted" };
    }
    
    return { valid: false, code: "INVALID_PEM", error: "Invalid PEM certificate" };
  }
}

/**
 * Validates a PEM private key (supports RSA and ECDSA; encrypted keys are not supported)
 */
export function validatePemPrivateKey(pem: string): PemValidationResult {
  // Normalize line endings and trim
  const trimmed = pem.replace(/\r\n/g, "\n").trim();

  // Common encrypted formats
  if (
    trimmed.includes("-----BEGIN ENCRYPTED PRIVATE KEY-----") ||
    trimmed.includes("Proc-Type: 4,ENCRYPTED")
  ) {
    return {
      valid: false,
      code: "ENCRYPTED_KEY",
      error: "Encrypted private keys are not supported. Please provide an unencrypted private key.",
    };
  }

  // Check for valid PEM header
  const hasValidHeader = 
    trimmed.includes("-----BEGIN PRIVATE KEY-----") ||
    trimmed.includes("-----BEGIN RSA PRIVATE KEY-----") ||
    trimmed.includes("-----BEGIN EC PRIVATE KEY-----");

  if (!hasValidHeader) {
    return { valid: false, code: "NO_PEM_BLOCK", error: "No valid private key PEM block found" };
  }

  try {
    // Try to decode the base64 content to verify it's valid
    const keyBuffer = pemToArrayBuffer(trimmed);
    if (keyBuffer.byteLength === 0) {
      return { valid: false, code: "INVALID_PEM", error: "Private key appears to be empty" };
    }
    
    // Basic size check - a valid private key should have reasonable size
    if (keyBuffer.byteLength < 32) {
      return { valid: false, code: "INVALID_PEM", error: "Private key data is too short" };
    }
    
    return { valid: true };
  } catch (err) {
    console.warn("Private key validation error:", err);
    return { valid: false, code: "INVALID_PEM", error: "Invalid PEM private key" };
  }
}

/**
 * Extracts certificate info for display (handles fullchain - uses first cert)
 * Supports both RSA and ECDSA certificates
 */
export function getCertificateInfo(pem: string): {
  subject: string;
  issuer: string;
  validFrom: Date;
  validTo: Date;
} | null {
  try {
    // Normalize line endings
    const normalized = pem.replace(/\r\n/g, "\n").trim();
    
    const firstCert = extractFirstCertificate(normalized);
    if (!firstCert) return null;
    
    const certBuffer = pemToArrayBuffer(firstCert);
    const cert = pkijs.Certificate.fromBER(certBuffer);
    
    // Extract CN from subject
    let subject = "Unknown";
    for (const rdn of cert.subject.typesAndValues) {
      if (rdn.type === "2.5.4.3") { // CN OID
        subject = rdn.value.valueBlock.value;
        break;
      }
    }
    
    // Extract CN from issuer
    let issuer = "Unknown";
    for (const rdn of cert.issuer.typesAndValues) {
      if (rdn.type === "2.5.4.3") { // CN OID
        issuer = rdn.value.valueBlock.value;
        break;
      }
    }
    
    return {
      subject,
      issuer,
      validFrom: cert.notBefore.value,
      validTo: cert.notAfter.value,
    };
  } catch (err) {
    console.warn("Failed to parse certificate info:", err);
    return null;
  }
}

/**
 * Parses multiple certificates from a chain file
 */
export function parseCertificateChain(pem: string): string[] {
  const certs: string[] = [];
  const regex = /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g;
  let match;

  while ((match = regex.exec(pem)) !== null) {
    certs.push(match[0]);
  }

  return certs;
}
