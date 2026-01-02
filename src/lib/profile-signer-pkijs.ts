import * as asn1js from "asn1js";
import * as pkijs from "pkijs";
import { Convert } from "pvtsutils";

export interface SigningConfig {
  signingCert: string; // PEM certificate
  privateKey: string; // PEM private key
  chainCerts: string[]; // Array of PEM certificates for the chain
}

/**
 * Decode PEM to ArrayBuffer
 */
function pemToArrayBuffer(pem: string): ArrayBuffer {
  // Remove PEM header/footer and whitespace
  const b64 = pem
    .replace(/-----BEGIN [^-]+-----/g, "")
    .replace(/-----END [^-]+-----/g, "")
    .replace(/\s/g, "");
  
  return Convert.FromBase64(b64);
}

/**
 * Extract the first certificate from a PEM string (handles fullchain)
 */
function extractFirstCertPem(pem: string): string | null {
  const match = pem.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/);
  return match ? match[0] : null;
}

/**
 * Get EC curve name from certificate's public key
 */
function getEcCurveFromCert(cert: pkijs.Certificate): string {
  try {
    const algorithmParams = cert.subjectPublicKeyInfo.algorithm.algorithmParams;
    if (!algorithmParams) return "P-384"; // Default fallback
    
    // The algorithmParams should be an OID for EC curves
    if (algorithmParams instanceof asn1js.ObjectIdentifier) {
      const oid = algorithmParams.valueBlock.toString();
      
      // Map OID to curve name
      switch (oid) {
        case "1.2.840.10045.3.1.7": return "P-256";
        case "1.3.132.0.34": return "P-384";
        case "1.3.132.0.35": return "P-521";
        default: return "P-384";
      }
    }
    
    // Try to get the OID string representation
    const oidStr = algorithmParams.valueBlock?.toString?.() || "";
    if (oidStr.includes("1.2.840.10045.3.1.7")) return "P-256";
    if (oidStr.includes("1.3.132.0.34")) return "P-384";
    if (oidStr.includes("1.3.132.0.35")) return "P-521";
    
    return "P-384"; // Default
  } catch {
    return "P-384"; // Safe default for Let's Encrypt ECDSA certs
  }
}

/**
 * Import private key with smart algorithm detection
 * Supports RSA and ECDSA (P-256, P-384, P-521)
 */
async function importPrivateKey(pem: string, cert: pkijs.Certificate): Promise<CryptoKey> {
  const keyBuffer = pemToArrayBuffer(pem);
  
  // Get algorithm info from certificate's public key
  const certAlgo = cert.subjectPublicKeyInfo.algorithm.algorithmId;
  
  // ECDSA OID
  const ecdsaOid = "1.2.840.10045.2.1"; // id-ecPublicKey
  // RSA OIDs
  const rsaOids = [
    "1.2.840.113549.1.1.1", // rsaEncryption
    "1.2.840.113549.1.1.11", // sha256WithRSAEncryption
  ];
  
  // Determine if ECDSA or RSA based on certificate
  const isEcdsa = certAlgo === ecdsaOid;
  const isRsa = rsaOids.includes(certAlgo);
  
  if (isEcdsa) {
    const namedCurve = getEcCurveFromCert(cert);
    console.log(`Detected EC curve: ${namedCurve}`);
    
    // Try the detected curve first, then fall back to others
    const curves = [namedCurve, "P-384", "P-256", "P-521"].filter((v, i, a) => a.indexOf(v) === i);
    
    for (const curve of curves) {
      try {
        return await crypto.subtle.importKey(
          "pkcs8",
          keyBuffer,
          { name: "ECDSA", namedCurve: curve },
          true,
          ["sign"]
        );
      } catch (e) {
        console.log(`Failed to import key with curve ${curve}:`, e);
      }
    }
    throw new Error("Failed to import EC private key. Ensure the key matches the certificate.");
  }
  
  if (isRsa) {
    return await crypto.subtle.importKey(
      "pkcs8",
      keyBuffer,
      { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
      true,
      ["sign"]
    );
  }
  
  // Unknown algorithm - try ECDSA first, then RSA
  const attempts: Array<{ name: string; params: AlgorithmIdentifier | EcKeyImportParams | RsaHashedImportParams }> = [
    { name: "ECDSA P-384", params: { name: "ECDSA", namedCurve: "P-384" } },
    { name: "ECDSA P-256", params: { name: "ECDSA", namedCurve: "P-256" } },
    { name: "ECDSA P-521", params: { name: "ECDSA", namedCurve: "P-521" } },
    { name: "RSA", params: { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" } },
  ];
  
  for (const attempt of attempts) {
    try {
      return await crypto.subtle.importKey("pkcs8", keyBuffer, attempt.params, true, ["sign"]);
    } catch {
      // Continue to next attempt
    }
  }
  
  throw new Error("Failed to import private key. Unsupported key type or format.");
}

/**
 * Signs a mobileconfig XML using S/MIME (PKCS#7/CMS)
 * Supports both RSA and ECDSA certificates via WebCrypto
 */
export async function signMobileConfig(
  xmlContent: string,
  config: SigningConfig
): Promise<Uint8Array> {
  try {
    // Extract first certificate from potentially fullchain PEM
    const firstCertPem = extractFirstCertPem(config.signingCert);
    if (!firstCertPem) {
      throw new Error("No valid certificate found in signing certificate");
    }
    
    // Parse the signing certificate
    const certBuffer = pemToArrayBuffer(firstCertPem);
    const signerCert = pkijs.Certificate.fromBER(certBuffer);
    
    // Import the private key using WebCrypto
    const privateKey = await importPrivateKey(config.privateKey, signerCert);
    
    // Determine hash algorithm - use SHA-384 for P-384 curves, SHA-256 otherwise
    const certAlgo = signerCert.subjectPublicKeyInfo.algorithm.algorithmId;
    const isEcdsa = certAlgo === "1.2.840.10045.2.1";
    let hashAlgorithm = "SHA-256";
    
    if (isEcdsa) {
      const curve = getEcCurveFromCert(signerCert);
      if (curve === "P-384") hashAlgorithm = "SHA-384";
      else if (curve === "P-521") hashAlgorithm = "SHA-512";
    }
    
    console.log(`Using hash algorithm: ${hashAlgorithm}`);
    
    // Convert XML content to ArrayBuffer
    const contentBuffer = new TextEncoder().encode(xmlContent);
    
    // Create CMS SignedData structure
    const cmsSignedData = new pkijs.SignedData({
      encapContentInfo: new pkijs.EncapsulatedContentInfo({
        eContentType: "1.2.840.113549.1.7.1", // id-data
        eContent: new asn1js.OctetString({ valueHex: contentBuffer.buffer }),
      }),
      signerInfos: [
        new pkijs.SignerInfo({
          sid: new pkijs.IssuerAndSerialNumber({
            issuer: signerCert.issuer,
            serialNumber: signerCert.serialNumber,
          }),
        }),
      ],
      certificates: [signerCert],
    });
    
    // Add chain certificates
    for (const chainCertPem of config.chainCerts) {
      try {
        const chainCertBuffer = pemToArrayBuffer(chainCertPem);
        const chainCert = pkijs.Certificate.fromBER(chainCertBuffer);
        cmsSignedData.certificates!.push(chainCert);
      } catch (e) {
        console.warn("Failed to parse chain certificate:", e);
      }
    }
    
    // Sign the data
    await cmsSignedData.sign(privateKey, 0, hashAlgorithm, contentBuffer.buffer);
    
    // Wrap in ContentInfo
    const contentInfo = new pkijs.ContentInfo({
      contentType: "1.2.840.113549.1.7.2", // id-signedData
      content: cmsSignedData.toSchema(true),
    });
    
    // Encode to DER
    const derBuffer = contentInfo.toSchema().toBER(false);
    
    return new Uint8Array(derBuffer);
  } catch (error) {
    console.error("Signing error:", error);
    throw new Error(
      `Failed to sign profile: ${error instanceof Error ? error.message : "Unknown error"}`
    );
  }
}

/**
 * Downloads a signed profile
 */
export function downloadSignedProfile(
  signedData: Uint8Array,
  filename: string
): void {
  const blob = new Blob([new Uint8Array(signedData)], {
    type: "application/x-apple-aspen-config",
  });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename.endsWith(".mobileconfig")
    ? filename
    : `${filename}.mobileconfig`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}
