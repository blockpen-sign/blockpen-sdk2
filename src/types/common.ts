export interface SignRequest {
    companyId: number;
    certificateFingerprint: string;
    data: Buffer;
    algorithm: 'SHA256' | 'KECCAK' | 'NONE';
  }
  
  export interface CertificateRequest {
    companyId: number;
    caFingerprint: string;
    options: {
      commonName: string;
      email: string;
      organization: string;
      country: string;
      isCA: boolean;
    };
  }