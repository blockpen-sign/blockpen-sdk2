import type { ColumnType } from "kysely";
export type Generated<T> = T extends ColumnType<infer S, infer I, infer U>
  ? ColumnType<S, I | undefined, U>
  : ColumnType<T, T | undefined, T>;
export type Timestamp = ColumnType<Date, Date | string, Date | string>;

export const UserRole = {
    ADMIN: "ADMIN",
    USER: "USER"
} as const;
export type UserRole = (typeof UserRole)[keyof typeof UserRole];
export const DocumentStatus = {
    DRAFT: "DRAFT",
    PENDING: "PENDING",
    COMPLETED: "COMPLETED",
    EXPIRED: "EXPIRED",
    REJECTED: "REJECTED",
    REVOKED: "REVOKED",
    SIGNED: "SIGNED"
} as const;
export type DocumentStatus = (typeof DocumentStatus)[keyof typeof DocumentStatus];
export const SignerStatus = {
    PENDING: "PENDING",
    SIGNED: "SIGNED",
    REJECTED: "REJECTED",
    EXPIRED: "EXPIRED"
} as const;
export type SignerStatus = (typeof SignerStatus)[keyof typeof SignerStatus];
export const FieldType = {
    SIGNATURE: "SIGNATURE",
    INITIAL: "INITIAL",
    DATE: "DATE",
    TEXT: "TEXT",
    CHECKBOX: "CHECKBOX"
} as const;
export type FieldType = (typeof FieldType)[keyof typeof FieldType];
export type ApiKey = {
    id: string;
    companyId: number;
    key: string;
    createdAt: Generated<Timestamp>;
    updatedAt: Timestamp;
    isActive: Generated<boolean>;
    isDeleted: Generated<boolean>;
    isRevoked: Generated<boolean>;
    lastUsed: Timestamp | null;
};
export type ApiKeyToUser = {
    A: string;
    B: string;
};
export type AuditLog = {
    id: string;
    documentId: string;
    action: string;
    userId: string | null;
    metadata: unknown | null;
    createdAt: Generated<Timestamp>;
};
export type BlockchainWallet = {
    id: string;
    companyId: number;
    address: string;
    privateKey: string | null;
    createdAt: Generated<Timestamp>;
    updatedAt: Timestamp;
};
export type Certificate = {
    id: string;
    companyId: number;
    fingerprint: string;
    publicKey: string;
    privateKey: string | null;
    isCA: Generated<boolean>;
    issuerCertId: string | null;
    validFrom: Timestamp;
    validTo: Timestamp;
    metadata: unknown | null;
    createdAt: Generated<Timestamp>;
    updatedAt: Timestamp;
};
export type Company = {
    id: number;
    name: string;
    adminEmail: string;
    country: string;
    rootCertificate: string | null;
    subscriptionId: string | null;
    createdAt: Generated<Timestamp>;
    updatedAt: Timestamp;
};
export type Document = {
    id: string;
    title: string | null;
    description: string | null;
    userId: string;
    companyId: number;
    status: Generated<DocumentStatus>;
    fileUrl: string;
    fileHash: string | null;
    blockchainDocId: string | null;
    templateId: string | null;
    metadata: unknown | null;
    expiresAt: Timestamp | null;
    createdAt: Generated<Timestamp>;
    updatedAt: Timestamp;
};
export type DocumentSigner = {
    id: string;
    documentId: string;
    email: string;
    name: string | null;
    order: number;
    status: Generated<SignerStatus>;
    expiresAt: Timestamp | null;
    notifiedAt: Timestamp | null;
    createdAt: Generated<Timestamp>;
    updatedAt: Timestamp;
    signatureId: string | null;
};
export type Signature = {
    id: string;
    documentId: string;
    userId: string;
    certificateId: string;
    signatureData: string;
    visualSignature: string | null;
    blockchainTx: string | null;
    coordinates: unknown | null;
    metadata: unknown | null;
    createdAt: Generated<Timestamp>;
    updatedAt: Timestamp;
};
export type SignatureField = {
    id: string;
    documentId: string;
    signerId: string;
    type: Generated<FieldType>;
    required: Generated<boolean>;
    page: number;
    x: number;
    y: number;
    width: number;
    height: number;
    signedAt: Timestamp | null;
    createdAt: Generated<Timestamp>;
    updatedAt: Timestamp;
};
export type SigningTemplate = {
    id: string;
    name: string;
    companyId: number;
    fields: unknown;
    createdAt: Generated<Timestamp>;
    updatedAt: Timestamp;
};
export type User = {
    id: string;
    email: string;
    name: string;
    companyId: number;
    role: Generated<UserRole>;
    createdAt: Generated<Timestamp>;
    updatedAt: Timestamp;
};
export type DB = {
    _ApiKeyToUser: ApiKeyToUser;
    api_keys: ApiKey;
    audit_logs: AuditLog;
    blockchain_wallets: BlockchainWallet;
    certificates: Certificate;
    companies: Company;
    document_signers: DocumentSigner;
    documents: Document;
    signature_fields: SignatureField;
    signatures: Signature;
    signing_templates: SigningTemplate;
    users: User;
};
