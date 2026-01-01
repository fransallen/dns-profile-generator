import forge from "node-forge";

export interface SigningConfig {
  signingCert: string; // PEM certificate
  privateKey: string; // PEM private key
  chainCerts: string[]; // Array of PEM certificates for the chain
}

/**
 * Signs a mobileconfig XML using S/MIME (PKCS#7)
 * Equivalent to: openssl smime -sign -signer cert -inkey key -certfile chain -nodetach -outform der
 */
export function signMobileConfig(
  xmlContent: string,
  config: SigningConfig
): Uint8Array {
  try {
    // Parse the signing certificate
    const signerCert = forge.pki.certificateFromPem(config.signingCert);

    // Parse the private key
    const privateKey = forge.pki.privateKeyFromPem(config.privateKey);

    // Create PKCS#7 signed data
    const p7 = forge.pkcs7.createSignedData();

    // Set the content to sign (the mobileconfig XML)
    p7.content = forge.util.createBuffer(xmlContent, "utf8");

    // Add the signer's certificate
    p7.addCertificate(signerCert);

    // Add chain certificates
    for (const chainCertPem of config.chainCerts) {
      try {
        const chainCert = forge.pki.certificateFromPem(chainCertPem);
        p7.addCertificate(chainCert);
      } catch (e) {
        console.warn("Failed to parse chain certificate:", e);
      }
    }

    // Add signer with authenticated attributes (similar to openssl smime defaults)
    p7.addSigner({
      key: privateKey,
      certificate: signerCert,
      digestAlgorithm: forge.pki.oids.sha256,
      authenticatedAttributes: [
        {
          type: forge.pki.oids.contentType,
          value: forge.pki.oids.data,
        },
        {
          type: forge.pki.oids.messageDigest,
          // value will be auto-populated at signing time
        },
        {
          type: forge.pki.oids.signingTime,
          value: new Date(),
        },
      ],
    });

    // Sign the data (attached/nodetach mode - content is included)
    p7.sign();

    // Convert to ASN.1 and then to DER
    const asn1 = p7.toAsn1();
    const derBytes = forge.asn1.toDer(asn1);

    // Convert to Uint8Array
    const buffer = new Uint8Array(derBytes.length());
    for (let i = 0; i < derBytes.length(); i++) {
      buffer[i] = derBytes.at(i);
    }

    return buffer;
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

/**
 * Validates a PEM certificate
 */
export function validatePemCertificate(pem: string): boolean {
  try {
    forge.pki.certificateFromPem(pem);
    return true;
  } catch {
    return false;
  }
}

/**
 * Validates a PEM private key
 */
export function validatePemPrivateKey(pem: string): boolean {
  try {
    forge.pki.privateKeyFromPem(pem);
    return true;
  } catch {
    return false;
  }
}

/**
 * Extracts certificate info for display
 */
export function getCertificateInfo(pem: string): {
  subject: string;
  issuer: string;
  validFrom: Date;
  validTo: Date;
} | null {
  try {
    const cert = forge.pki.certificateFromPem(pem);
    return {
      subject: cert.subject.getField("CN")?.value || "Unknown",
      issuer: cert.issuer.getField("CN")?.value || "Unknown",
      validFrom: cert.validity.notBefore,
      validTo: cert.validity.notAfter,
    };
  } catch {
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
