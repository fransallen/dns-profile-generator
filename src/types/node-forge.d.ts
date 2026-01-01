declare module "node-forge" {
  export const pki: {
    certificateFromPem(pem: string): Certificate;
    privateKeyFromPem(pem: string): PrivateKey;
    oids: {
      data: string;
      sha256: string;
      contentType: string;
      messageDigest: string;
      signingTime: string;
    };
  };

  export const pkcs7: {
    createSignedData(): PKCS7SignedData;
  };

  export const util: {
    createBuffer(data: string, encoding?: string): ByteStringBuffer;
  };

  export const asn1: {
    toDer(obj: unknown): ByteStringBuffer;
  };

  interface Certificate {
    subject: {
      getField(name: string): { value: string } | null;
    };
    issuer: {
      getField(name: string): { value: string } | null;
    };
    validity: {
      notBefore: Date;
      notAfter: Date;
    };
  }

  interface PrivateKey {}

  interface PKCS7SignedData {
    content: ByteStringBuffer;
    addCertificate(cert: Certificate | string): void;
    addSigner(options: {
      key: PrivateKey;
      certificate: Certificate | string;
      digestAlgorithm: string;
      authenticatedAttributes: Array<{
        type: string;
        value?: unknown;
      }>;
    }): void;
    sign(): void;
    toAsn1(): unknown;
  }

  interface ByteStringBuffer {
    length(): number;
    at(index: number): number;
    getBytes(): string;
  }
}
