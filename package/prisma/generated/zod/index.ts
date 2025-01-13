import { z } from 'zod';
import { Prisma } from '@prisma/client';

/////////////////////////////////////////
// HELPER FUNCTIONS
/////////////////////////////////////////

// JSON
//------------------------------------------------------

export type NullableJsonInput = Prisma.JsonValue | null | 'JsonNull' | 'DbNull' | Prisma.NullTypes.DbNull | Prisma.NullTypes.JsonNull;

export const transformJsonNull = (v?: NullableJsonInput) => {
  if (!v || v === 'DbNull') return Prisma.DbNull;
  if (v === 'JsonNull') return Prisma.JsonNull;
  return v;
};

export const JsonValueSchema: z.ZodType<Prisma.JsonValue> = z.lazy(() =>
  z.union([
    z.string(),
    z.number(),
    z.boolean(),
    z.literal(null),
    z.record(z.lazy(() => JsonValueSchema.optional())),
    z.array(z.lazy(() => JsonValueSchema)),
  ])
);

export type JsonValueType = z.infer<typeof JsonValueSchema>;

export const NullableJsonValue = z
  .union([JsonValueSchema, z.literal('DbNull'), z.literal('JsonNull')])
  .nullable()
  .transform((v) => transformJsonNull(v));

export type NullableJsonValueType = z.infer<typeof NullableJsonValue>;

export const InputJsonValueSchema: z.ZodType<Prisma.InputJsonValue> = z.lazy(() =>
  z.union([
    z.string(),
    z.number(),
    z.boolean(),
    z.object({ toJSON: z.function(z.tuple([]), z.any()) }),
    z.record(z.lazy(() => z.union([InputJsonValueSchema, z.literal(null)]))),
    z.array(z.lazy(() => z.union([InputJsonValueSchema, z.literal(null)]))),
  ])
);

export type InputJsonValueType = z.infer<typeof InputJsonValueSchema>;


/////////////////////////////////////////
// ENUMS
/////////////////////////////////////////

export const TransactionIsolationLevelSchema = z.enum(['ReadUncommitted','ReadCommitted','RepeatableRead','Serializable']);

export const UserScalarFieldEnumSchema = z.enum(['id','email','name','companyId','role','createdAt','updatedAt']);

export const CompanyScalarFieldEnumSchema = z.enum(['id','name','adminEmail','country','rootCertificate','subscriptionId','createdAt','updatedAt']);

export const DocumentScalarFieldEnumSchema = z.enum(['id','title','description','userId','companyId','status','fileUrl','fileHash','blockchainDocId','templateId','metadata','expiresAt','createdAt','updatedAt']);

export const DocumentSignerScalarFieldEnumSchema = z.enum(['id','documentId','email','name','order','status','expiresAt','notifiedAt','createdAt','updatedAt','signatureId']);

export const SignatureFieldScalarFieldEnumSchema = z.enum(['id','documentId','signerId','type','required','page','x','y','width','height','signedAt','createdAt','updatedAt']);

export const SignatureScalarFieldEnumSchema = z.enum(['id','documentId','userId','certificateId','signatureData','visualSignature','blockchainTx','coordinates','metadata','createdAt','updatedAt']);

export const CertificateScalarFieldEnumSchema = z.enum(['id','companyId','fingerprint','publicKey','privateKey','isCA','issuerCertId','validFrom','validTo','metadata','createdAt','updatedAt']);

export const SigningTemplateScalarFieldEnumSchema = z.enum(['id','name','companyId','fields','createdAt','updatedAt']);

export const BlockchainWalletScalarFieldEnumSchema = z.enum(['id','companyId','address','privateKey','createdAt','updatedAt']);

export const ApiKeyScalarFieldEnumSchema = z.enum(['id','companyId','key','createdAt','updatedAt','isActive','isDeleted','isRevoked','lastUsed']);

export const AuditLogScalarFieldEnumSchema = z.enum(['id','documentId','action','userId','metadata','createdAt']);

export const SortOrderSchema = z.enum(['asc','desc']);

export const NullableJsonNullValueInputSchema = z.enum(['DbNull','JsonNull',]).transform((value) => value === 'JsonNull' ? Prisma.JsonNull : value === 'DbNull' ? Prisma.DbNull : value);

export const JsonNullValueInputSchema = z.enum(['JsonNull',]).transform((value) => (value === 'JsonNull' ? Prisma.JsonNull : value));

export const QueryModeSchema = z.enum(['default','insensitive']);

export const NullsOrderSchema = z.enum(['first','last']);

export const JsonNullValueFilterSchema = z.enum(['DbNull','JsonNull','AnyNull',]).transform((value) => value === 'JsonNull' ? Prisma.JsonNull : value === 'DbNull' ? Prisma.JsonNull : value === 'AnyNull' ? Prisma.AnyNull : value);

export const UserRoleSchema = z.enum(['ADMIN','USER']);

export type UserRoleType = `${z.infer<typeof UserRoleSchema>}`

export const DocumentStatusSchema = z.enum(['DRAFT','PENDING','COMPLETED','EXPIRED','REJECTED','REVOKED','SIGNED']);

export type DocumentStatusType = `${z.infer<typeof DocumentStatusSchema>}`

export const SignerStatusSchema = z.enum(['PENDING','SIGNED','REJECTED','EXPIRED']);

export type SignerStatusType = `${z.infer<typeof SignerStatusSchema>}`

export const FieldTypeSchema = z.enum(['SIGNATURE','INITIAL','DATE','TEXT','CHECKBOX']);

export type FieldTypeType = `${z.infer<typeof FieldTypeSchema>}`

/////////////////////////////////////////
// MODELS
/////////////////////////////////////////

/////////////////////////////////////////
// USER SCHEMA
/////////////////////////////////////////

export const UserSchema = z.object({
  role: UserRoleSchema,
  id: z.string().uuid(),
  email: z.string(),
  name: z.string(),
  companyId: z.number().int(),
  createdAt: z.coerce.date(),
  updatedAt: z.coerce.date(),
})

export type User = z.infer<typeof UserSchema>

/////////////////////////////////////////
// COMPANY SCHEMA
/////////////////////////////////////////

export const CompanySchema = z.object({
  id: z.number().int(),
  name: z.string(),
  adminEmail: z.string(),
  country: z.string(),
  rootCertificate: z.string().nullable(),
  subscriptionId: z.string().nullable(),
  createdAt: z.coerce.date(),
  updatedAt: z.coerce.date(),
})

export type Company = z.infer<typeof CompanySchema>

/////////////////////////////////////////
// DOCUMENT SCHEMA
/////////////////////////////////////////

export const DocumentSchema = z.object({
  status: DocumentStatusSchema,
  id: z.string().uuid(),
  title: z.string().nullable(),
  description: z.string().nullable(),
  userId: z.string(),
  companyId: z.number().int(),
  fileUrl: z.string(),
  fileHash: z.string().nullable(),
  blockchainDocId: z.string().nullable(),
  templateId: z.string().nullable(),
  metadata: JsonValueSchema.nullable(),
  expiresAt: z.coerce.date().nullable(),
  createdAt: z.coerce.date(),
  updatedAt: z.coerce.date(),
})

export type Document = z.infer<typeof DocumentSchema>

/////////////////////////////////////////
// DOCUMENT SIGNER SCHEMA
/////////////////////////////////////////

export const DocumentSignerSchema = z.object({
  status: SignerStatusSchema,
  id: z.string().uuid(),
  documentId: z.string(),
  email: z.string(),
  name: z.string().nullable(),
  order: z.number().int(),
  expiresAt: z.coerce.date().nullable(),
  notifiedAt: z.coerce.date().nullable(),
  createdAt: z.coerce.date(),
  updatedAt: z.coerce.date(),
  signatureId: z.string().nullable(),
})

export type DocumentSigner = z.infer<typeof DocumentSignerSchema>

/////////////////////////////////////////
// SIGNATURE FIELD SCHEMA
/////////////////////////////////////////

export const SignatureFieldSchema = z.object({
  type: FieldTypeSchema,
  id: z.string().uuid(),
  documentId: z.string(),
  signerId: z.string(),
  required: z.boolean(),
  page: z.number().int(),
  x: z.number(),
  y: z.number(),
  width: z.number(),
  height: z.number(),
  signedAt: z.coerce.date().nullable(),
  createdAt: z.coerce.date(),
  updatedAt: z.coerce.date(),
})

export type SignatureField = z.infer<typeof SignatureFieldSchema>

/////////////////////////////////////////
// SIGNATURE SCHEMA
/////////////////////////////////////////

export const SignatureSchema = z.object({
  id: z.string().uuid(),
  documentId: z.string(),
  userId: z.string(),
  certificateId: z.string(),
  signatureData: z.string(),
  visualSignature: z.string().nullable(),
  blockchainTx: z.string().nullable(),
  coordinates: JsonValueSchema.nullable(),
  metadata: JsonValueSchema.nullable(),
  createdAt: z.coerce.date(),
  updatedAt: z.coerce.date(),
})

export type Signature = z.infer<typeof SignatureSchema>

/////////////////////////////////////////
// CERTIFICATE SCHEMA
/////////////////////////////////////////

export const CertificateSchema = z.object({
  id: z.string().uuid(),
  companyId: z.number().int(),
  fingerprint: z.string(),
  publicKey: z.string(),
  privateKey: z.string().nullable(),
  isCA: z.boolean(),
  issuerCertId: z.string().nullable(),
  validFrom: z.coerce.date(),
  validTo: z.coerce.date(),
  metadata: JsonValueSchema.nullable(),
  createdAt: z.coerce.date(),
  updatedAt: z.coerce.date(),
})

export type Certificate = z.infer<typeof CertificateSchema>

/////////////////////////////////////////
// SIGNING TEMPLATE SCHEMA
/////////////////////////////////////////

export const SigningTemplateSchema = z.object({
  id: z.string().uuid(),
  name: z.string(),
  companyId: z.number().int(),
  fields: JsonValueSchema,
  createdAt: z.coerce.date(),
  updatedAt: z.coerce.date(),
})

export type SigningTemplate = z.infer<typeof SigningTemplateSchema>

/////////////////////////////////////////
// BLOCKCHAIN WALLET SCHEMA
/////////////////////////////////////////

export const BlockchainWalletSchema = z.object({
  id: z.string().uuid(),
  companyId: z.number().int(),
  address: z.string(),
  privateKey: z.string().nullable(),
  createdAt: z.coerce.date(),
  updatedAt: z.coerce.date(),
})

export type BlockchainWallet = z.infer<typeof BlockchainWalletSchema>

/////////////////////////////////////////
// API KEY SCHEMA
/////////////////////////////////////////

export const ApiKeySchema = z.object({
  id: z.string().uuid(),
  companyId: z.number().int(),
  key: z.string(),
  createdAt: z.coerce.date(),
  updatedAt: z.coerce.date(),
  isActive: z.boolean(),
  isDeleted: z.boolean(),
  isRevoked: z.boolean(),
  lastUsed: z.coerce.date().nullable(),
})

export type ApiKey = z.infer<typeof ApiKeySchema>

/////////////////////////////////////////
// AUDIT LOG SCHEMA
/////////////////////////////////////////

export const AuditLogSchema = z.object({
  id: z.string().uuid(),
  documentId: z.string(),
  action: z.string(),
  userId: z.string().nullable(),
  metadata: JsonValueSchema.nullable(),
  createdAt: z.coerce.date(),
})

export type AuditLog = z.infer<typeof AuditLogSchema>

/////////////////////////////////////////
// SELECT & INCLUDE
/////////////////////////////////////////

// USER
//------------------------------------------------------

export const UserIncludeSchema: z.ZodType<Prisma.UserInclude> = z.object({
  company: z.union([z.boolean(),z.lazy(() => CompanyArgsSchema)]).optional(),
  documents: z.union([z.boolean(),z.lazy(() => DocumentFindManyArgsSchema)]).optional(),
  signatures: z.union([z.boolean(),z.lazy(() => SignatureFindManyArgsSchema)]).optional(),
  apiKeys: z.union([z.boolean(),z.lazy(() => ApiKeyFindManyArgsSchema)]).optional(),
  _count: z.union([z.boolean(),z.lazy(() => UserCountOutputTypeArgsSchema)]).optional(),
}).strict()

export const UserArgsSchema: z.ZodType<Prisma.UserDefaultArgs> = z.object({
  select: z.lazy(() => UserSelectSchema).optional(),
  include: z.lazy(() => UserIncludeSchema).optional(),
}).strict();

export const UserCountOutputTypeArgsSchema: z.ZodType<Prisma.UserCountOutputTypeDefaultArgs> = z.object({
  select: z.lazy(() => UserCountOutputTypeSelectSchema).nullish(),
}).strict();

export const UserCountOutputTypeSelectSchema: z.ZodType<Prisma.UserCountOutputTypeSelect> = z.object({
  documents: z.boolean().optional(),
  signatures: z.boolean().optional(),
  apiKeys: z.boolean().optional(),
}).strict();

export const UserSelectSchema: z.ZodType<Prisma.UserSelect> = z.object({
  id: z.boolean().optional(),
  email: z.boolean().optional(),
  name: z.boolean().optional(),
  companyId: z.boolean().optional(),
  role: z.boolean().optional(),
  createdAt: z.boolean().optional(),
  updatedAt: z.boolean().optional(),
  company: z.union([z.boolean(),z.lazy(() => CompanyArgsSchema)]).optional(),
  documents: z.union([z.boolean(),z.lazy(() => DocumentFindManyArgsSchema)]).optional(),
  signatures: z.union([z.boolean(),z.lazy(() => SignatureFindManyArgsSchema)]).optional(),
  apiKeys: z.union([z.boolean(),z.lazy(() => ApiKeyFindManyArgsSchema)]).optional(),
  _count: z.union([z.boolean(),z.lazy(() => UserCountOutputTypeArgsSchema)]).optional(),
}).strict()

// COMPANY
//------------------------------------------------------

export const CompanyIncludeSchema: z.ZodType<Prisma.CompanyInclude> = z.object({
  users: z.union([z.boolean(),z.lazy(() => UserFindManyArgsSchema)]).optional(),
  documents: z.union([z.boolean(),z.lazy(() => DocumentFindManyArgsSchema)]).optional(),
  certificates: z.union([z.boolean(),z.lazy(() => CertificateFindManyArgsSchema)]).optional(),
  blockchainWallet: z.union([z.boolean(),z.lazy(() => BlockchainWalletArgsSchema)]).optional(),
  SigningTemplate: z.union([z.boolean(),z.lazy(() => SigningTemplateFindManyArgsSchema)]).optional(),
  ApiKey: z.union([z.boolean(),z.lazy(() => ApiKeyFindManyArgsSchema)]).optional(),
  _count: z.union([z.boolean(),z.lazy(() => CompanyCountOutputTypeArgsSchema)]).optional(),
}).strict()

export const CompanyArgsSchema: z.ZodType<Prisma.CompanyDefaultArgs> = z.object({
  select: z.lazy(() => CompanySelectSchema).optional(),
  include: z.lazy(() => CompanyIncludeSchema).optional(),
}).strict();

export const CompanyCountOutputTypeArgsSchema: z.ZodType<Prisma.CompanyCountOutputTypeDefaultArgs> = z.object({
  select: z.lazy(() => CompanyCountOutputTypeSelectSchema).nullish(),
}).strict();

export const CompanyCountOutputTypeSelectSchema: z.ZodType<Prisma.CompanyCountOutputTypeSelect> = z.object({
  users: z.boolean().optional(),
  documents: z.boolean().optional(),
  certificates: z.boolean().optional(),
  SigningTemplate: z.boolean().optional(),
  ApiKey: z.boolean().optional(),
}).strict();

export const CompanySelectSchema: z.ZodType<Prisma.CompanySelect> = z.object({
  id: z.boolean().optional(),
  name: z.boolean().optional(),
  adminEmail: z.boolean().optional(),
  country: z.boolean().optional(),
  rootCertificate: z.boolean().optional(),
  subscriptionId: z.boolean().optional(),
  createdAt: z.boolean().optional(),
  updatedAt: z.boolean().optional(),
  users: z.union([z.boolean(),z.lazy(() => UserFindManyArgsSchema)]).optional(),
  documents: z.union([z.boolean(),z.lazy(() => DocumentFindManyArgsSchema)]).optional(),
  certificates: z.union([z.boolean(),z.lazy(() => CertificateFindManyArgsSchema)]).optional(),
  blockchainWallet: z.union([z.boolean(),z.lazy(() => BlockchainWalletArgsSchema)]).optional(),
  SigningTemplate: z.union([z.boolean(),z.lazy(() => SigningTemplateFindManyArgsSchema)]).optional(),
  ApiKey: z.union([z.boolean(),z.lazy(() => ApiKeyFindManyArgsSchema)]).optional(),
  _count: z.union([z.boolean(),z.lazy(() => CompanyCountOutputTypeArgsSchema)]).optional(),
}).strict()

// DOCUMENT
//------------------------------------------------------

export const DocumentIncludeSchema: z.ZodType<Prisma.DocumentInclude> = z.object({
  user: z.union([z.boolean(),z.lazy(() => UserArgsSchema)]).optional(),
  company: z.union([z.boolean(),z.lazy(() => CompanyArgsSchema)]).optional(),
  signingTemplate: z.union([z.boolean(),z.lazy(() => SigningTemplateArgsSchema)]).optional(),
  signers: z.union([z.boolean(),z.lazy(() => DocumentSignerFindManyArgsSchema)]).optional(),
  signatures: z.union([z.boolean(),z.lazy(() => SignatureFindManyArgsSchema)]).optional(),
  auditLogs: z.union([z.boolean(),z.lazy(() => AuditLogFindManyArgsSchema)]).optional(),
  SignatureField: z.union([z.boolean(),z.lazy(() => SignatureFieldFindManyArgsSchema)]).optional(),
  _count: z.union([z.boolean(),z.lazy(() => DocumentCountOutputTypeArgsSchema)]).optional(),
}).strict()

export const DocumentArgsSchema: z.ZodType<Prisma.DocumentDefaultArgs> = z.object({
  select: z.lazy(() => DocumentSelectSchema).optional(),
  include: z.lazy(() => DocumentIncludeSchema).optional(),
}).strict();

export const DocumentCountOutputTypeArgsSchema: z.ZodType<Prisma.DocumentCountOutputTypeDefaultArgs> = z.object({
  select: z.lazy(() => DocumentCountOutputTypeSelectSchema).nullish(),
}).strict();

export const DocumentCountOutputTypeSelectSchema: z.ZodType<Prisma.DocumentCountOutputTypeSelect> = z.object({
  signers: z.boolean().optional(),
  signatures: z.boolean().optional(),
  auditLogs: z.boolean().optional(),
  SignatureField: z.boolean().optional(),
}).strict();

export const DocumentSelectSchema: z.ZodType<Prisma.DocumentSelect> = z.object({
  id: z.boolean().optional(),
  title: z.boolean().optional(),
  description: z.boolean().optional(),
  userId: z.boolean().optional(),
  companyId: z.boolean().optional(),
  status: z.boolean().optional(),
  fileUrl: z.boolean().optional(),
  fileHash: z.boolean().optional(),
  blockchainDocId: z.boolean().optional(),
  templateId: z.boolean().optional(),
  metadata: z.boolean().optional(),
  expiresAt: z.boolean().optional(),
  createdAt: z.boolean().optional(),
  updatedAt: z.boolean().optional(),
  user: z.union([z.boolean(),z.lazy(() => UserArgsSchema)]).optional(),
  company: z.union([z.boolean(),z.lazy(() => CompanyArgsSchema)]).optional(),
  signingTemplate: z.union([z.boolean(),z.lazy(() => SigningTemplateArgsSchema)]).optional(),
  signers: z.union([z.boolean(),z.lazy(() => DocumentSignerFindManyArgsSchema)]).optional(),
  signatures: z.union([z.boolean(),z.lazy(() => SignatureFindManyArgsSchema)]).optional(),
  auditLogs: z.union([z.boolean(),z.lazy(() => AuditLogFindManyArgsSchema)]).optional(),
  SignatureField: z.union([z.boolean(),z.lazy(() => SignatureFieldFindManyArgsSchema)]).optional(),
  _count: z.union([z.boolean(),z.lazy(() => DocumentCountOutputTypeArgsSchema)]).optional(),
}).strict()

// DOCUMENT SIGNER
//------------------------------------------------------

export const DocumentSignerIncludeSchema: z.ZodType<Prisma.DocumentSignerInclude> = z.object({
  document: z.union([z.boolean(),z.lazy(() => DocumentArgsSchema)]).optional(),
  signatureFields: z.union([z.boolean(),z.lazy(() => SignatureFieldFindManyArgsSchema)]).optional(),
  signature: z.union([z.boolean(),z.lazy(() => SignatureArgsSchema)]).optional(),
  _count: z.union([z.boolean(),z.lazy(() => DocumentSignerCountOutputTypeArgsSchema)]).optional(),
}).strict()

export const DocumentSignerArgsSchema: z.ZodType<Prisma.DocumentSignerDefaultArgs> = z.object({
  select: z.lazy(() => DocumentSignerSelectSchema).optional(),
  include: z.lazy(() => DocumentSignerIncludeSchema).optional(),
}).strict();

export const DocumentSignerCountOutputTypeArgsSchema: z.ZodType<Prisma.DocumentSignerCountOutputTypeDefaultArgs> = z.object({
  select: z.lazy(() => DocumentSignerCountOutputTypeSelectSchema).nullish(),
}).strict();

export const DocumentSignerCountOutputTypeSelectSchema: z.ZodType<Prisma.DocumentSignerCountOutputTypeSelect> = z.object({
  signatureFields: z.boolean().optional(),
}).strict();

export const DocumentSignerSelectSchema: z.ZodType<Prisma.DocumentSignerSelect> = z.object({
  id: z.boolean().optional(),
  documentId: z.boolean().optional(),
  email: z.boolean().optional(),
  name: z.boolean().optional(),
  order: z.boolean().optional(),
  status: z.boolean().optional(),
  expiresAt: z.boolean().optional(),
  notifiedAt: z.boolean().optional(),
  createdAt: z.boolean().optional(),
  updatedAt: z.boolean().optional(),
  signatureId: z.boolean().optional(),
  document: z.union([z.boolean(),z.lazy(() => DocumentArgsSchema)]).optional(),
  signatureFields: z.union([z.boolean(),z.lazy(() => SignatureFieldFindManyArgsSchema)]).optional(),
  signature: z.union([z.boolean(),z.lazy(() => SignatureArgsSchema)]).optional(),
  _count: z.union([z.boolean(),z.lazy(() => DocumentSignerCountOutputTypeArgsSchema)]).optional(),
}).strict()

// SIGNATURE FIELD
//------------------------------------------------------

export const SignatureFieldIncludeSchema: z.ZodType<Prisma.SignatureFieldInclude> = z.object({
  document: z.union([z.boolean(),z.lazy(() => DocumentArgsSchema)]).optional(),
  signer: z.union([z.boolean(),z.lazy(() => DocumentSignerArgsSchema)]).optional(),
}).strict()

export const SignatureFieldArgsSchema: z.ZodType<Prisma.SignatureFieldDefaultArgs> = z.object({
  select: z.lazy(() => SignatureFieldSelectSchema).optional(),
  include: z.lazy(() => SignatureFieldIncludeSchema).optional(),
}).strict();

export const SignatureFieldSelectSchema: z.ZodType<Prisma.SignatureFieldSelect> = z.object({
  id: z.boolean().optional(),
  documentId: z.boolean().optional(),
  signerId: z.boolean().optional(),
  type: z.boolean().optional(),
  required: z.boolean().optional(),
  page: z.boolean().optional(),
  x: z.boolean().optional(),
  y: z.boolean().optional(),
  width: z.boolean().optional(),
  height: z.boolean().optional(),
  signedAt: z.boolean().optional(),
  createdAt: z.boolean().optional(),
  updatedAt: z.boolean().optional(),
  document: z.union([z.boolean(),z.lazy(() => DocumentArgsSchema)]).optional(),
  signer: z.union([z.boolean(),z.lazy(() => DocumentSignerArgsSchema)]).optional(),
}).strict()

// SIGNATURE
//------------------------------------------------------

export const SignatureIncludeSchema: z.ZodType<Prisma.SignatureInclude> = z.object({
  document: z.union([z.boolean(),z.lazy(() => DocumentArgsSchema)]).optional(),
  user: z.union([z.boolean(),z.lazy(() => UserArgsSchema)]).optional(),
  certificate: z.union([z.boolean(),z.lazy(() => CertificateArgsSchema)]).optional(),
  DocumentSigner: z.union([z.boolean(),z.lazy(() => DocumentSignerFindManyArgsSchema)]).optional(),
  _count: z.union([z.boolean(),z.lazy(() => SignatureCountOutputTypeArgsSchema)]).optional(),
}).strict()

export const SignatureArgsSchema: z.ZodType<Prisma.SignatureDefaultArgs> = z.object({
  select: z.lazy(() => SignatureSelectSchema).optional(),
  include: z.lazy(() => SignatureIncludeSchema).optional(),
}).strict();

export const SignatureCountOutputTypeArgsSchema: z.ZodType<Prisma.SignatureCountOutputTypeDefaultArgs> = z.object({
  select: z.lazy(() => SignatureCountOutputTypeSelectSchema).nullish(),
}).strict();

export const SignatureCountOutputTypeSelectSchema: z.ZodType<Prisma.SignatureCountOutputTypeSelect> = z.object({
  DocumentSigner: z.boolean().optional(),
}).strict();

export const SignatureSelectSchema: z.ZodType<Prisma.SignatureSelect> = z.object({
  id: z.boolean().optional(),
  documentId: z.boolean().optional(),
  userId: z.boolean().optional(),
  certificateId: z.boolean().optional(),
  signatureData: z.boolean().optional(),
  visualSignature: z.boolean().optional(),
  blockchainTx: z.boolean().optional(),
  coordinates: z.boolean().optional(),
  metadata: z.boolean().optional(),
  createdAt: z.boolean().optional(),
  updatedAt: z.boolean().optional(),
  document: z.union([z.boolean(),z.lazy(() => DocumentArgsSchema)]).optional(),
  user: z.union([z.boolean(),z.lazy(() => UserArgsSchema)]).optional(),
  certificate: z.union([z.boolean(),z.lazy(() => CertificateArgsSchema)]).optional(),
  DocumentSigner: z.union([z.boolean(),z.lazy(() => DocumentSignerFindManyArgsSchema)]).optional(),
  _count: z.union([z.boolean(),z.lazy(() => SignatureCountOutputTypeArgsSchema)]).optional(),
}).strict()

// CERTIFICATE
//------------------------------------------------------

export const CertificateIncludeSchema: z.ZodType<Prisma.CertificateInclude> = z.object({
  company: z.union([z.boolean(),z.lazy(() => CompanyArgsSchema)]).optional(),
  signatures: z.union([z.boolean(),z.lazy(() => SignatureFindManyArgsSchema)]).optional(),
  _count: z.union([z.boolean(),z.lazy(() => CertificateCountOutputTypeArgsSchema)]).optional(),
}).strict()

export const CertificateArgsSchema: z.ZodType<Prisma.CertificateDefaultArgs> = z.object({
  select: z.lazy(() => CertificateSelectSchema).optional(),
  include: z.lazy(() => CertificateIncludeSchema).optional(),
}).strict();

export const CertificateCountOutputTypeArgsSchema: z.ZodType<Prisma.CertificateCountOutputTypeDefaultArgs> = z.object({
  select: z.lazy(() => CertificateCountOutputTypeSelectSchema).nullish(),
}).strict();

export const CertificateCountOutputTypeSelectSchema: z.ZodType<Prisma.CertificateCountOutputTypeSelect> = z.object({
  signatures: z.boolean().optional(),
}).strict();

export const CertificateSelectSchema: z.ZodType<Prisma.CertificateSelect> = z.object({
  id: z.boolean().optional(),
  companyId: z.boolean().optional(),
  fingerprint: z.boolean().optional(),
  publicKey: z.boolean().optional(),
  privateKey: z.boolean().optional(),
  isCA: z.boolean().optional(),
  issuerCertId: z.boolean().optional(),
  validFrom: z.boolean().optional(),
  validTo: z.boolean().optional(),
  metadata: z.boolean().optional(),
  createdAt: z.boolean().optional(),
  updatedAt: z.boolean().optional(),
  company: z.union([z.boolean(),z.lazy(() => CompanyArgsSchema)]).optional(),
  signatures: z.union([z.boolean(),z.lazy(() => SignatureFindManyArgsSchema)]).optional(),
  _count: z.union([z.boolean(),z.lazy(() => CertificateCountOutputTypeArgsSchema)]).optional(),
}).strict()

// SIGNING TEMPLATE
//------------------------------------------------------

export const SigningTemplateIncludeSchema: z.ZodType<Prisma.SigningTemplateInclude> = z.object({
  company: z.union([z.boolean(),z.lazy(() => CompanyArgsSchema)]).optional(),
  documents: z.union([z.boolean(),z.lazy(() => DocumentFindManyArgsSchema)]).optional(),
  _count: z.union([z.boolean(),z.lazy(() => SigningTemplateCountOutputTypeArgsSchema)]).optional(),
}).strict()

export const SigningTemplateArgsSchema: z.ZodType<Prisma.SigningTemplateDefaultArgs> = z.object({
  select: z.lazy(() => SigningTemplateSelectSchema).optional(),
  include: z.lazy(() => SigningTemplateIncludeSchema).optional(),
}).strict();

export const SigningTemplateCountOutputTypeArgsSchema: z.ZodType<Prisma.SigningTemplateCountOutputTypeDefaultArgs> = z.object({
  select: z.lazy(() => SigningTemplateCountOutputTypeSelectSchema).nullish(),
}).strict();

export const SigningTemplateCountOutputTypeSelectSchema: z.ZodType<Prisma.SigningTemplateCountOutputTypeSelect> = z.object({
  documents: z.boolean().optional(),
}).strict();

export const SigningTemplateSelectSchema: z.ZodType<Prisma.SigningTemplateSelect> = z.object({
  id: z.boolean().optional(),
  name: z.boolean().optional(),
  companyId: z.boolean().optional(),
  fields: z.boolean().optional(),
  createdAt: z.boolean().optional(),
  updatedAt: z.boolean().optional(),
  company: z.union([z.boolean(),z.lazy(() => CompanyArgsSchema)]).optional(),
  documents: z.union([z.boolean(),z.lazy(() => DocumentFindManyArgsSchema)]).optional(),
  _count: z.union([z.boolean(),z.lazy(() => SigningTemplateCountOutputTypeArgsSchema)]).optional(),
}).strict()

// BLOCKCHAIN WALLET
//------------------------------------------------------

export const BlockchainWalletIncludeSchema: z.ZodType<Prisma.BlockchainWalletInclude> = z.object({
  company: z.union([z.boolean(),z.lazy(() => CompanyArgsSchema)]).optional(),
}).strict()

export const BlockchainWalletArgsSchema: z.ZodType<Prisma.BlockchainWalletDefaultArgs> = z.object({
  select: z.lazy(() => BlockchainWalletSelectSchema).optional(),
  include: z.lazy(() => BlockchainWalletIncludeSchema).optional(),
}).strict();

export const BlockchainWalletSelectSchema: z.ZodType<Prisma.BlockchainWalletSelect> = z.object({
  id: z.boolean().optional(),
  companyId: z.boolean().optional(),
  address: z.boolean().optional(),
  privateKey: z.boolean().optional(),
  createdAt: z.boolean().optional(),
  updatedAt: z.boolean().optional(),
  company: z.union([z.boolean(),z.lazy(() => CompanyArgsSchema)]).optional(),
}).strict()

// API KEY
//------------------------------------------------------

export const ApiKeyIncludeSchema: z.ZodType<Prisma.ApiKeyInclude> = z.object({
  company: z.union([z.boolean(),z.lazy(() => CompanyArgsSchema)]).optional(),
  user: z.union([z.boolean(),z.lazy(() => UserFindManyArgsSchema)]).optional(),
  _count: z.union([z.boolean(),z.lazy(() => ApiKeyCountOutputTypeArgsSchema)]).optional(),
}).strict()

export const ApiKeyArgsSchema: z.ZodType<Prisma.ApiKeyDefaultArgs> = z.object({
  select: z.lazy(() => ApiKeySelectSchema).optional(),
  include: z.lazy(() => ApiKeyIncludeSchema).optional(),
}).strict();

export const ApiKeyCountOutputTypeArgsSchema: z.ZodType<Prisma.ApiKeyCountOutputTypeDefaultArgs> = z.object({
  select: z.lazy(() => ApiKeyCountOutputTypeSelectSchema).nullish(),
}).strict();

export const ApiKeyCountOutputTypeSelectSchema: z.ZodType<Prisma.ApiKeyCountOutputTypeSelect> = z.object({
  user: z.boolean().optional(),
}).strict();

export const ApiKeySelectSchema: z.ZodType<Prisma.ApiKeySelect> = z.object({
  id: z.boolean().optional(),
  companyId: z.boolean().optional(),
  key: z.boolean().optional(),
  createdAt: z.boolean().optional(),
  updatedAt: z.boolean().optional(),
  isActive: z.boolean().optional(),
  isDeleted: z.boolean().optional(),
  isRevoked: z.boolean().optional(),
  lastUsed: z.boolean().optional(),
  company: z.union([z.boolean(),z.lazy(() => CompanyArgsSchema)]).optional(),
  user: z.union([z.boolean(),z.lazy(() => UserFindManyArgsSchema)]).optional(),
  _count: z.union([z.boolean(),z.lazy(() => ApiKeyCountOutputTypeArgsSchema)]).optional(),
}).strict()

// AUDIT LOG
//------------------------------------------------------

export const AuditLogIncludeSchema: z.ZodType<Prisma.AuditLogInclude> = z.object({
  document: z.union([z.boolean(),z.lazy(() => DocumentArgsSchema)]).optional(),
}).strict()

export const AuditLogArgsSchema: z.ZodType<Prisma.AuditLogDefaultArgs> = z.object({
  select: z.lazy(() => AuditLogSelectSchema).optional(),
  include: z.lazy(() => AuditLogIncludeSchema).optional(),
}).strict();

export const AuditLogSelectSchema: z.ZodType<Prisma.AuditLogSelect> = z.object({
  id: z.boolean().optional(),
  documentId: z.boolean().optional(),
  action: z.boolean().optional(),
  userId: z.boolean().optional(),
  metadata: z.boolean().optional(),
  createdAt: z.boolean().optional(),
  document: z.union([z.boolean(),z.lazy(() => DocumentArgsSchema)]).optional(),
}).strict()


/////////////////////////////////////////
// INPUT TYPES
/////////////////////////////////////////

export const UserWhereInputSchema: z.ZodType<Prisma.UserWhereInput> = z.object({
  AND: z.union([ z.lazy(() => UserWhereInputSchema),z.lazy(() => UserWhereInputSchema).array() ]).optional(),
  OR: z.lazy(() => UserWhereInputSchema).array().optional(),
  NOT: z.union([ z.lazy(() => UserWhereInputSchema),z.lazy(() => UserWhereInputSchema).array() ]).optional(),
  id: z.union([ z.lazy(() => StringFilterSchema),z.string() ]).optional(),
  email: z.union([ z.lazy(() => StringFilterSchema),z.string() ]).optional(),
  name: z.union([ z.lazy(() => StringFilterSchema),z.string() ]).optional(),
  companyId: z.union([ z.lazy(() => IntFilterSchema),z.number() ]).optional(),
  role: z.union([ z.lazy(() => EnumUserRoleFilterSchema),z.lazy(() => UserRoleSchema) ]).optional(),
  createdAt: z.union([ z.lazy(() => DateTimeFilterSchema),z.coerce.date() ]).optional(),
  updatedAt: z.union([ z.lazy(() => DateTimeFilterSchema),z.coerce.date() ]).optional(),
  company: z.union([ z.lazy(() => CompanyScalarRelationFilterSchema),z.lazy(() => CompanyWhereInputSchema) ]).optional(),
  documents: z.lazy(() => DocumentListRelationFilterSchema).optional(),
  signatures: z.lazy(() => SignatureListRelationFilterSchema).optional(),
  apiKeys: z.lazy(() => ApiKeyListRelationFilterSchema).optional()
}).strict();

export const UserOrderByWithRelationInputSchema: z.ZodType<Prisma.UserOrderByWithRelationInput> = z.object({
  id: z.lazy(() => SortOrderSchema).optional(),
  email: z.lazy(() => SortOrderSchema).optional(),
  name: z.lazy(() => SortOrderSchema).optional(),
  companyId: z.lazy(() => SortOrderSchema).optional(),
  role: z.lazy(() => SortOrderSchema).optional(),
  createdAt: z.lazy(() => SortOrderSchema).optional(),
  updatedAt: z.lazy(() => SortOrderSchema).optional(),
  company: z.lazy(() => CompanyOrderByWithRelationInputSchema).optional(),
  documents: z.lazy(() => DocumentOrderByRelationAggregateInputSchema).optional(),
  signatures: z.lazy(() => SignatureOrderByRelationAggregateInputSchema).optional(),
  apiKeys: z.lazy(() => ApiKeyOrderByRelationAggregateInputSchema).optional()
}).strict();

export const UserWhereUniqueInputSchema: z.ZodType<Prisma.UserWhereUniqueInput> = z.union([
  z.object({
    id: z.string().uuid(),
    email: z.string()
  }),
  z.object({
    id: z.string().uuid(),
  }),
  z.object({
    email: z.string(),
  }),
])
.and(z.object({
  id: z.string().uuid().optional(),
  email: z.string().optional(),
  AND: z.union([ z.lazy(() => UserWhereInputSchema),z.lazy(() => UserWhereInputSchema).array() ]).optional(),
  OR: z.lazy(() => UserWhereInputSchema).array().optional(),
  NOT: z.union([ z.lazy(() => UserWhereInputSchema),z.lazy(() => UserWhereInputSchema).array() ]).optional(),
  name: z.union([ z.lazy(() => StringFilterSchema),z.string() ]).optional(),
  companyId: z.union([ z.lazy(() => IntFilterSchema),z.number().int() ]).optional(),
  role: z.union([ z.lazy(() => EnumUserRoleFilterSchema),z.lazy(() => UserRoleSchema) ]).optional(),
  createdAt: z.union([ z.lazy(() => DateTimeFilterSchema),z.coerce.date() ]).optional(),
  updatedAt: z.union([ z.lazy(() => DateTimeFilterSchema),z.coerce.date() ]).optional(),
  company: z.union([ z.lazy(() => CompanyScalarRelationFilterSchema),z.lazy(() => CompanyWhereInputSchema) ]).optional(),
  documents: z.lazy(() => DocumentListRelationFilterSchema).optional(),
  signatures: z.lazy(() => SignatureListRelationFilterSchema).optional(),
  apiKeys: z.lazy(() => ApiKeyListRelationFilterSchema).optional()
}).strict());

export const UserOrderByWithAggregationInputSchema: z.ZodType<Prisma.UserOrderByWithAggregationInput> = z.object({
  id: z.lazy(() => SortOrderSchema).optional(),
  email: z.lazy(() => SortOrderSchema).optional(),
  name: z.lazy(() => SortOrderSchema).optional(),
  companyId: z.lazy(() => SortOrderSchema).optional(),
  role: z.lazy(() => SortOrderSchema).optional(),
  createdAt: z.lazy(() => SortOrderSchema).optional(),
  updatedAt: z.lazy(() => SortOrderSchema).optional(),
  _count: z.lazy(() => UserCountOrderByAggregateInputSchema).optional(),
  _avg: z.lazy(() => UserAvgOrderByAggregateInputSchema).optional(),
  _max: z.lazy(() => UserMaxOrderByAggregateInputSchema).optional(),
  _min: z.lazy(() => UserMinOrderByAggregateInputSchema).optional(),
  _sum: z.lazy(() => UserSumOrderByAggregateInputSchema).optional()
}).strict();

export const UserScalarWhereWithAggregatesInputSchema: z.ZodType<Prisma.UserScalarWhereWithAggregatesInput> = z.object({
  AND: z.union([ z.lazy(() => UserScalarWhereWithAggregatesInputSchema),z.lazy(() => UserScalarWhereWithAggregatesInputSchema).array() ]).optional(),
  OR: z.lazy(() => UserScalarWhereWithAggregatesInputSchema).array().optional(),
  NOT: z.union([ z.lazy(() => UserScalarWhereWithAggregatesInputSchema),z.lazy(() => UserScalarWhereWithAggregatesInputSchema).array() ]).optional(),
  id: z.union([ z.lazy(() => StringWithAggregatesFilterSchema),z.string() ]).optional(),
  email: z.union([ z.lazy(() => StringWithAggregatesFilterSchema),z.string() ]).optional(),
  name: z.union([ z.lazy(() => StringWithAggregatesFilterSchema),z.string() ]).optional(),
  companyId: z.union([ z.lazy(() => IntWithAggregatesFilterSchema),z.number() ]).optional(),
  role: z.union([ z.lazy(() => EnumUserRoleWithAggregatesFilterSchema),z.lazy(() => UserRoleSchema) ]).optional(),
  createdAt: z.union([ z.lazy(() => DateTimeWithAggregatesFilterSchema),z.coerce.date() ]).optional(),
  updatedAt: z.union([ z.lazy(() => DateTimeWithAggregatesFilterSchema),z.coerce.date() ]).optional(),
}).strict();

export const CompanyWhereInputSchema: z.ZodType<Prisma.CompanyWhereInput> = z.object({
  AND: z.union([ z.lazy(() => CompanyWhereInputSchema),z.lazy(() => CompanyWhereInputSchema).array() ]).optional(),
  OR: z.lazy(() => CompanyWhereInputSchema).array().optional(),
  NOT: z.union([ z.lazy(() => CompanyWhereInputSchema),z.lazy(() => CompanyWhereInputSchema).array() ]).optional(),
  id: z.union([ z.lazy(() => IntFilterSchema),z.number() ]).optional(),
  name: z.union([ z.lazy(() => StringFilterSchema),z.string() ]).optional(),
  adminEmail: z.union([ z.lazy(() => StringFilterSchema),z.string() ]).optional(),
  country: z.union([ z.lazy(() => StringFilterSchema),z.string() ]).optional(),
  rootCertificate: z.union([ z.lazy(() => StringNullableFilterSchema),z.string() ]).optional().nullable(),
  subscriptionId: z.union([ z.lazy(() => StringNullableFilterSchema),z.string() ]).optional().nullable(),
  createdAt: z.union([ z.lazy(() => DateTimeFilterSchema),z.coerce.date() ]).optional(),
  updatedAt: z.union([ z.lazy(() => DateTimeFilterSchema),z.coerce.date() ]).optional(),
  users: z.lazy(() => UserListRelationFilterSchema).optional(),
  documents: z.lazy(() => DocumentListRelationFilterSchema).optional(),
  certificates: z.lazy(() => CertificateListRelationFilterSchema).optional(),
  blockchainWallet: z.union([ z.lazy(() => BlockchainWalletNullableScalarRelationFilterSchema),z.lazy(() => BlockchainWalletWhereInputSchema) ]).optional().nullable(),
  SigningTemplate: z.lazy(() => SigningTemplateListRelationFilterSchema).optional(),
  ApiKey: z.lazy(() => ApiKeyListRelationFilterSchema).optional()
}).strict();

export const CompanyOrderByWithRelationInputSchema: z.ZodType<Prisma.CompanyOrderByWithRelationInput> = z.object({
  id: z.lazy(() => SortOrderSchema).optional(),
  name: z.lazy(() => SortOrderSchema).optional(),
  adminEmail: z.lazy(() => SortOrderSchema).optional(),
  country: z.lazy(() => SortOrderSchema).optional(),
  rootCertificate: z.union([ z.lazy(() => SortOrderSchema),z.lazy(() => SortOrderInputSchema) ]).optional(),
  subscriptionId: z.union([ z.lazy(() => SortOrderSchema),z.lazy(() => SortOrderInputSchema) ]).optional(),
  createdAt: z.lazy(() => SortOrderSchema).optional(),
  updatedAt: z.lazy(() => SortOrderSchema).optional(),
  users: z.lazy(() => UserOrderByRelationAggregateInputSchema).optional(),
  documents: z.lazy(() => DocumentOrderByRelationAggregateInputSchema).optional(),
  certificates: z.lazy(() => CertificateOrderByRelationAggregateInputSchema).optional(),
  blockchainWallet: z.lazy(() => BlockchainWalletOrderByWithRelationInputSchema).optional(),
  SigningTemplate: z.lazy(() => SigningTemplateOrderByRelationAggregateInputSchema).optional(),
  ApiKey: z.lazy(() => ApiKeyOrderByRelationAggregateInputSchema).optional()
}).strict();

export const CompanyWhereUniqueInputSchema: z.ZodType<Prisma.CompanyWhereUniqueInput> = z.object({
  id: z.number().int()
})
.and(z.object({
  id: z.number().int().optional(),
  AND: z.union([ z.lazy(() => CompanyWhereInputSchema),z.lazy(() => CompanyWhereInputSchema).array() ]).optional(),
  OR: z.lazy(() => CompanyWhereInputSchema).array().optional(),
  NOT: z.union([ z.lazy(() => CompanyWhereInputSchema),z.lazy(() => CompanyWhereInputSchema).array() ]).optional(),
  name: z.union([ z.lazy(() => StringFilterSchema),z.string() ]).optional(),
  adminEmail: z.union([ z.lazy(() => StringFilterSchema),z.string() ]).optional(),
  country: z.union([ z.lazy(() => StringFilterSchema),z.string() ]).optional(),
  rootCertificate: z.union([ z.lazy(() => StringNullableFilterSchema),z.string() ]).optional().nullable(),
  subscriptionId: z.union([ z.lazy(() => StringNullableFilterSchema),z.string() ]).optional().nullable(),
  createdAt: z.union([ z.lazy(() => DateTimeFilterSchema),z.coerce.date() ]).optional(),
  updatedAt: z.union([ z.lazy(() => DateTimeFilterSchema),z.coerce.date() ]).optional(),
  users: z.lazy(() => UserListRelationFilterSchema).optional(),
  documents: z.lazy(() => DocumentListRelationFilterSchema).optional(),
  certificates: z.lazy(() => CertificateListRelationFilterSchema).optional(),
  blockchainWallet: z.union([ z.lazy(() => BlockchainWalletNullableScalarRelationFilterSchema),z.lazy(() => BlockchainWalletWhereInputSchema) ]).optional().nullable(),
  SigningTemplate: z.lazy(() => SigningTemplateListRelationFilterSchema).optional(),
  ApiKey: z.lazy(() => ApiKeyListRelationFilterSchema).optional()
}).strict());

export const CompanyOrderByWithAggregationInputSchema: z.ZodType<Prisma.CompanyOrderByWithAggregationInput> = z.object({
  id: z.lazy(() => SortOrderSchema).optional(),
  name: z.lazy(() => SortOrderSchema).optional(),
  adminEmail: z.lazy(() => SortOrderSchema).optional(),
  country: z.lazy(() => SortOrderSchema).optional(),
  rootCertificate: z.union([ z.lazy(() => SortOrderSchema),z.lazy(() => SortOrderInputSchema) ]).optional(),
  subscriptionId: z.union([ z.lazy(() => SortOrderSchema),z.lazy(() => SortOrderInputSchema) ]).optional(),
  createdAt: z.lazy(() => SortOrderSchema).optional(),
  updatedAt: z.lazy(() => SortOrderSchema).optional(),
  _count: z.lazy(() => CompanyCountOrderByAggregateInputSchema).optional(),
  _avg: z.lazy(() => CompanyAvgOrderByAggregateInputSchema).optional(),
  _max: z.lazy(() => CompanyMaxOrderByAggregateInputSchema).optional(),
  _min: z.lazy(() => CompanyMinOrderByAggregateInputSchema).optional(),
  _sum: z.lazy(() => CompanySumOrderByAggregateInputSchema).optional()
}).strict();

export const CompanyScalarWhereWithAggregatesInputSchema: z.ZodType<Prisma.CompanyScalarWhereWithAggregatesInput> = z.object({
  AND: z.union([ z.lazy(() => CompanyScalarWhereWithAggregatesInputSchema),z.lazy(() => CompanyScalarWhereWithAggregatesInputSchema).array() ]).optional(),
  OR: z.lazy(() => CompanyScalarWhereWithAggregatesInputSchema).array().optional(),
  NOT: z.union([ z.lazy(() => CompanyScalarWhereWithAggregatesInputSchema),z.lazy(() => CompanyScalarWhereWithAggregatesInputSchema).array() ]).optional(),
  id: z.union([ z.lazy(() => IntWithAggregatesFilterSchema),z.number() ]).optional(),
  name: z.union([ z.lazy(() => StringWithAggregatesFilterSchema),z.string() ]).optional(),
  adminEmail: z.union([ z.lazy(() => StringWithAggregatesFilterSchema),z.string() ]).optional(),
  country: z.union([ z.lazy(() => StringWithAggregatesFilterSchema),z.string() ]).optional(),
  rootCertificate: z.union([ z.lazy(() => StringNullableWithAggregatesFilterSchema),z.string() ]).optional().nullable(),
  subscriptionId: z.union([ z.lazy(() => StringNullableWithAggregatesFilterSchema),z.string() ]).optional().nullable(),
  createdAt: z.union([ z.lazy(() => DateTimeWithAggregatesFilterSchema),z.coerce.date() ]).optional(),
  updatedAt: z.union([ z.lazy(() => DateTimeWithAggregatesFilterSchema),z.coerce.date() ]).optional(),
}).strict();

export const DocumentWhereInputSchema: z.ZodType<Prisma.DocumentWhereInput> = z.object({
  AND: z.union([ z.lazy(() => DocumentWhereInputSchema),z.lazy(() => DocumentWhereInputSchema).array() ]).optional(),
  OR: z.lazy(() => DocumentWhereInputSchema).array().optional(),
  NOT: z.union([ z.lazy(() => DocumentWhereInputSchema),z.lazy(() => DocumentWhereInputSchema).array() ]).optional(),
  id: z.union([ z.lazy(() => StringFilterSchema),z.string() ]).optional(),
  title: z.union([ z.lazy(() => StringNullableFilterSchema),z.string() ]).optional().nullable(),
  description: z.union([ z.lazy(() => StringNullableFilterSchema),z.string() ]).optional().nullable(),
  userId: z.union([ z.lazy(() => StringFilterSchema),z.string() ]).optional(),
  companyId: z.union([ z.lazy(() => IntFilterSchema),z.number() ]).optional(),
  status: z.union([ z.lazy(() => EnumDocumentStatusFilterSchema),z.lazy(() => DocumentStatusSchema) ]).optional(),
  fileUrl: z.union([ z.lazy(() => StringFilterSchema),z.string() ]).optional(),
  fileHash: z.union([ z.lazy(() => StringNullableFilterSchema),z.string() ]).optional().nullable(),
  blockchainDocId: z.union([ z.lazy(() => StringNullableFilterSchema),z.string() ]).optional().nullable(),
  templateId: z.union([ z.lazy(() => StringNullableFilterSchema),z.string() ]).optional().nullable(),
  metadata: z.lazy(() => JsonNullableFilterSchema).optional(),
  expiresAt: z.union([ z.lazy(() => DateTimeNullableFilterSchema),z.coerce.date() ]).optional().nullable(),
  createdAt: z.union([ z.lazy(() => DateTimeFilterSchema),z.coerce.date() ]).optional(),
  updatedAt: z.union([ z.lazy(() => DateTimeFilterSchema),z.coerce.date() ]).optional(),
  user: z.union([ z.lazy(() => UserScalarRelationFilterSchema),z.lazy(() => UserWhereInputSchema) ]).optional(),
  company: z.union([ z.lazy(() => CompanyScalarRelationFilterSchema),z.lazy(() => CompanyWhereInputSchema) ]).optional(),
  signingTemplate: z.union([ z.lazy(() => SigningTemplateNullableScalarRelationFilterSchema),z.lazy(() => SigningTemplateWhereInputSchema) ]).optional().nullable(),
  signers: z.lazy(() => DocumentSignerListRelationFilterSchema).optional(),
  signatures: z.lazy(() => SignatureListRelationFilterSchema).optional(),
  auditLogs: z.lazy(() => AuditLogListRelationFilterSchema).optional(),
  SignatureField: z.lazy(() => SignatureFieldListRelationFilterSchema).optional()
}).strict();

export const DocumentOrderByWithRelationInputSchema: z.ZodType<Prisma.DocumentOrderByWithRelationInput> = z.object({
  id: z.lazy(() => SortOrderSchema).optional(),
  title: z.union([ z.lazy(() => SortOrderSchema),z.lazy(() => SortOrderInputSchema) ]).optional(),
  description: z.union([ z.lazy(() => SortOrderSchema),z.lazy(() => SortOrderInputSchema) ]).optional(),
  userId: z.lazy(() => SortOrderSchema).optional(),
  companyId: z.lazy(() => SortOrderSchema).optional(),
  status: z.lazy(() => SortOrderSchema).optional(),
  fileUrl: z.lazy(() => SortOrderSchema).optional(),
  fileHash: z.union([ z.lazy(() => SortOrderSchema),z.lazy(() => SortOrderInputSchema) ]).optional(),
  blockchainDocId: z.union([ z.lazy(() => SortOrderSchema),z.lazy(() => SortOrderInputSchema) ]).optional(),
  templateId: z.union([ z.lazy(() => SortOrderSchema),z.lazy(() => SortOrderInputSchema) ]).optional(),
  metadata: z.union([ z.lazy(() => SortOrderSchema),z.lazy(() => SortOrderInputSchema) ]).optional(),
  expiresAt: z.union([ z.lazy(() => SortOrderSchema),z.lazy(() => SortOrderInputSchema) ]).optional(),
  createdAt: z.lazy(() => SortOrderSchema).optional(),
  updatedAt: z.lazy(() => SortOrderSchema).optional(),
  user: z.lazy(() => UserOrderByWithRelationInputSchema).optional(),
  company: z.lazy(() => CompanyOrderByWithRelationInputSchema).optional(),
  signingTemplate: z.lazy(() => SigningTemplateOrderByWithRelationInputSchema).optional(),
  signers: z.lazy(() => DocumentSignerOrderByRelationAggregateInputSchema).optional(),
  signatures: z.lazy(() => SignatureOrderByRelationAggregateInputSchema).optional(),
  auditLogs: z.lazy(() => AuditLogOrderByRelationAggregateInputSchema).optional(),
  SignatureField: z.lazy(() => SignatureFieldOrderByRelationAggregateInputSchema).optional()
}).strict();

export const DocumentWhereUniqueInputSchema: z.ZodType<Prisma.DocumentWhereUniqueInput> = z.object({
  id: z.string().uuid()
})
.and(z.object({
  id: z.string().uuid().optional(),
  AND: z.union([ z.lazy(() => DocumentWhereInputSchema),z.lazy(() => DocumentWhereInputSchema).array() ]).optional(),
  OR: z.lazy(() => DocumentWhereInputSchema).array().optional(),
  NOT: z.union([ z.lazy(() => DocumentWhereInputSchema),z.lazy(() => DocumentWhereInputSchema).array() ]).optional(),
  title: z.union([ z.lazy(() => StringNullableFilterSchema),z.string() ]).optional().nullable(),
  description: z.union([ z.lazy(() => StringNullableFilterSchema),z.string() ]).optional().nullable(),
  userId: z.union([ z.lazy(() => StringFilterSchema),z.string() ]).optional(),
  companyId: z.union([ z.lazy(() => IntFilterSchema),z.number().int() ]).optional(),
  status: z.union([ z.lazy(() => EnumDocumentStatusFilterSchema),z.lazy(() => DocumentStatusSchema) ]).optional(),
  fileUrl: z.union([ z.lazy(() => StringFilterSchema),z.string() ]).optional(),
  fileHash: z.union([ z.lazy(() => StringNullableFilterSchema),z.string() ]).optional().nullable(),
  blockchainDocId: z.union([ z.lazy(() => StringNullableFilterSchema),z.string() ]).optional().nullable(),
  templateId: z.union([ z.lazy(() => StringNullableFilterSchema),z.string() ]).optional().nullable(),
  metadata: z.lazy(() => JsonNullableFilterSchema).optional(),
  expiresAt: z.union([ z.lazy(() => DateTimeNullableFilterSchema),z.coerce.date() ]).optional().nullable(),
  createdAt: z.union([ z.lazy(() => DateTimeFilterSchema),z.coerce.date() ]).optional(),
  updatedAt: z.union([ z.lazy(() => DateTimeFilterSchema),z.coerce.date() ]).optional(),
  user: z.union([ z.lazy(() => UserScalarRelationFilterSchema),z.lazy(() => UserWhereInputSchema) ]).optional(),
  company: z.union([ z.lazy(() => CompanyScalarRelationFilterSchema),z.lazy(() => CompanyWhereInputSchema) ]).optional(),
  signingTemplate: z.union([ z.lazy(() => SigningTemplateNullableScalarRelationFilterSchema),z.lazy(() => SigningTemplateWhereInputSchema) ]).optional().nullable(),
  signers: z.lazy(() => DocumentSignerListRelationFilterSchema).optional(),
  signatures: z.lazy(() => SignatureListRelationFilterSchema).optional(),
  auditLogs: z.lazy(() => AuditLogListRelationFilterSchema).optional(),
  SignatureField: z.lazy(() => SignatureFieldListRelationFilterSchema).optional()
}).strict());

export const DocumentOrderByWithAggregationInputSchema: z.ZodType<Prisma.DocumentOrderByWithAggregationInput> = z.object({
  id: z.lazy(() => SortOrderSchema).optional(),
  title: z.union([ z.lazy(() => SortOrderSchema),z.lazy(() => SortOrderInputSchema) ]).optional(),
  description: z.union([ z.lazy(() => SortOrderSchema),z.lazy(() => SortOrderInputSchema) ]).optional(),
  userId: z.lazy(() => SortOrderSchema).optional(),
  companyId: z.lazy(() => SortOrderSchema).optional(),
  status: z.lazy(() => SortOrderSchema).optional(),
  fileUrl: z.lazy(() => SortOrderSchema).optional(),
  fileHash: z.union([ z.lazy(() => SortOrderSchema),z.lazy(() => SortOrderInputSchema) ]).optional(),
  blockchainDocId: z.union([ z.lazy(() => SortOrderSchema),z.lazy(() => SortOrderInputSchema) ]).optional(),
  templateId: z.union([ z.lazy(() => SortOrderSchema),z.lazy(() => SortOrderInputSchema) ]).optional(),
  metadata: z.union([ z.lazy(() => SortOrderSchema),z.lazy(() => SortOrderInputSchema) ]).optional(),
  expiresAt: z.union([ z.lazy(() => SortOrderSchema),z.lazy(() => SortOrderInputSchema) ]).optional(),
  createdAt: z.lazy(() => SortOrderSchema).optional(),
  updatedAt: z.lazy(() => SortOrderSchema).optional(),
  _count: z.lazy(() => DocumentCountOrderByAggregateInputSchema).optional(),
  _avg: z.lazy(() => DocumentAvgOrderByAggregateInputSchema).optional(),
  _max: z.lazy(() => DocumentMaxOrderByAggregateInputSchema).optional(),
  _min: z.lazy(() => DocumentMinOrderByAggregateInputSchema).optional(),
  _sum: z.lazy(() => DocumentSumOrderByAggregateInputSchema).optional()
}).strict();

export const DocumentScalarWhereWithAggregatesInputSchema: z.ZodType<Prisma.DocumentScalarWhereWithAggregatesInput> = z.object({
  AND: z.union([ z.lazy(() => DocumentScalarWhereWithAggregatesInputSchema),z.lazy(() => DocumentScalarWhereWithAggregatesInputSchema).array() ]).optional(),
  OR: z.lazy(() => DocumentScalarWhereWithAggregatesInputSchema).array().optional(),
  NOT: z.union([ z.lazy(() => DocumentScalarWhereWithAggregatesInputSchema),z.lazy(() => DocumentScalarWhereWithAggregatesInputSchema).array() ]).optional(),
  id: z.union([ z.lazy(() => StringWithAggregatesFilterSchema),z.string() ]).optional(),
  title: z.union([ z.lazy(() => StringNullableWithAggregatesFilterSchema),z.string() ]).optional().nullable(),
  description: z.union([ z.lazy(() => StringNullableWithAggregatesFilterSchema),z.string() ]).optional().nullable(),
  userId: z.union([ z.lazy(() => StringWithAggregatesFilterSchema),z.string() ]).optional(),
  companyId: z.union([ z.lazy(() => IntWithAggregatesFilterSchema),z.number() ]).optional(),
  status: z.union([ z.lazy(() => EnumDocumentStatusWithAggregatesFilterSchema),z.lazy(() => DocumentStatusSchema) ]).optional(),
  fileUrl: z.union([ z.lazy(() => StringWithAggregatesFilterSchema),z.string() ]).optional(),
  fileHash: z.union([ z.lazy(() => StringNullableWithAggregatesFilterSchema),z.string() ]).optional().nullable(),
  blockchainDocId: z.union([ z.lazy(() => StringNullableWithAggregatesFilterSchema),z.string() ]).optional().nullable(),
  templateId: z.union([ z.lazy(() => StringNullableWithAggregatesFilterSchema),z.string() ]).optional().nullable(),
  metadata: z.lazy(() => JsonNullableWithAggregatesFilterSchema).optional(),
  expiresAt: z.union([ z.lazy(() => DateTimeNullableWithAggregatesFilterSchema),z.coerce.date() ]).optional().nullable(),
  createdAt: z.union([ z.lazy(() => DateTimeWithAggregatesFilterSchema),z.coerce.date() ]).optional(),
  updatedAt: z.union([ z.lazy(() => DateTimeWithAggregatesFilterSchema),z.coerce.date() ]).optional(),
}).strict();

export const DocumentSignerWhereInputSchema: z.ZodType<Prisma.DocumentSignerWhereInput> = z.object({
  AND: z.union([ z.lazy(() => DocumentSignerWhereInputSchema),z.lazy(() => DocumentSignerWhereInputSchema).array() ]).optional(),
  OR: z.lazy(() => DocumentSignerWhereInputSchema).array().optional(),
  NOT: z.union([ z.lazy(() => DocumentSignerWhereInputSchema),z.lazy(() => DocumentSignerWhereInputSchema).array() ]).optional(),
  id: z.union([ z.lazy(() => StringFilterSchema),z.string() ]).optional(),
  documentId: z.union([ z.lazy(() => StringFilterSchema),z.string() ]).optional(),
  email: z.union([ z.lazy(() => StringFilterSchema),z.string() ]).optional(),
  name: z.union([ z.lazy(() => StringNullableFilterSchema),z.string() ]).optional().nullable(),
  order: z.union([ z.lazy(() => IntFilterSchema),z.number() ]).optional(),
  status: z.union([ z.lazy(() => EnumSignerStatusFilterSchema),z.lazy(() => SignerStatusSchema) ]).optional(),
  expiresAt: z.union([ z.lazy(() => DateTimeNullableFilterSchema),z.coerce.date() ]).optional().nullable(),
  notifiedAt: z.union([ z.lazy(() => DateTimeNullableFilterSchema),z.coerce.date() ]).optional().nullable(),
  createdAt: z.union([ z.lazy(() => DateTimeFilterSchema),z.coerce.date() ]).optional(),
  updatedAt: z.union([ z.lazy(() => DateTimeFilterSchema),z.coerce.date() ]).optional(),
  signatureId: z.union([ z.lazy(() => StringNullableFilterSchema),z.string() ]).optional().nullable(),
  document: z.union([ z.lazy(() => DocumentScalarRelationFilterSchema),z.lazy(() => DocumentWhereInputSchema) ]).optional(),
  signatureFields: z.lazy(() => SignatureFieldListRelationFilterSchema).optional(),
  signature: z.union([ z.lazy(() => SignatureNullableScalarRelationFilterSchema),z.lazy(() => SignatureWhereInputSchema) ]).optional().nullable(),
}).strict();

export const DocumentSignerOrderByWithRelationInputSchema: z.ZodType<Prisma.DocumentSignerOrderByWithRelationInput> = z.object({
  id: z.lazy(() => SortOrderSchema).optional(),
  documentId: z.lazy(() => SortOrderSchema).optional(),
  email: z.lazy(() => SortOrderSchema).optional(),
  name: z.union([ z.lazy(() => SortOrderSchema),z.lazy(() => SortOrderInputSchema) ]).optional(),
  order: z.lazy(() => SortOrderSchema).optional(),
  status: z.lazy(() => SortOrderSchema).optional(),
  expiresAt: z.union([ z.lazy(() => SortOrderSchema),z.lazy(() => SortOrderInputSchema) ]).optional(),
  notifiedAt: z.union([ z.lazy(() => SortOrderSchema),z.lazy(() => SortOrderInputSchema) ]).optional(),
  createdAt: z.lazy(() => SortOrderSchema).optional(),
  updatedAt: z.lazy(() => SortOrderSchema).optional(),
  signatureId: z.union([ z.lazy(() => SortOrderSchema),z.lazy(() => SortOrderInputSchema) ]).optional(),
  document: z.lazy(() => DocumentOrderByWithRelationInputSchema).optional(),
  signatureFields: z.lazy(() => SignatureFieldOrderByRelationAggregateInputSchema).optional(),
  signature: z.lazy(() => SignatureOrderByWithRelationInputSchema).optional()
}).strict();

export const DocumentSignerWhereUniqueInputSchema: z.ZodType<Prisma.DocumentSignerWhereUniqueInput> = z.object({
  id: z.string().uuid()
})
.and(z.object({
  id: z.string().uuid().optional(),
  AND: z.union([ z.lazy(() => DocumentSignerWhereInputSchema),z.lazy(() => DocumentSignerWhereInputSchema).array() ]).optional(),
  OR: z.lazy(() => DocumentSignerWhereInputSchema).array().optional(),
  NOT: z.union([ z.lazy(() => DocumentSignerWhereInputSchema),z.lazy(() => DocumentSignerWhereInputSchema).array() ]).optional(),
  documentId: z.union([ z.lazy(() => StringFilterSchema),z.string() ]).optional(),
  email: z.union([ z.lazy(() => StringFilterSchema),z.string() ]).optional(),
  name: z.union([ z.lazy(() => StringNullableFilterSchema),z.string() ]).optional().nullable(),
  order: z.union([ z.lazy(() => IntFilterSchema),z.number().int() ]).optional(),
  status: z.union([ z.lazy(() => EnumSignerStatusFilterSchema),z.lazy(() => SignerStatusSchema) ]).optional(),
  expiresAt: z.union([ z.lazy(() => DateTimeNullableFilterSchema),z.coerce.date() ]).optional().nullable(),
  notifiedAt: z.union([ z.lazy(() => DateTimeNullableFilterSchema),z.coerce.date() ]).optional().nullable(),
  createdAt: z.union([ z.lazy(() => DateTimeFilterSchema),z.coerce.date() ]).optional(),
  updatedAt: z.union([ z.lazy(() => DateTimeFilterSchema),z.coerce.date() ]).optional(),
  signatureId: z.union([ z.lazy(() => StringNullableFilterSchema),z.string() ]).optional().nullable(),
  document: z.union([ z.lazy(() => DocumentScalarRelationFilterSchema),z.lazy(() => DocumentWhereInputSchema) ]).optional(),
  signatureFields: z.lazy(() => SignatureFieldListRelationFilterSchema).optional(),
  signature: z.union([ z.lazy(() => SignatureNullableScalarRelationFilterSchema),z.lazy(() => SignatureWhereInputSchema) ]).optional().nullable(),
}).strict());

export const DocumentSignerOrderByWithAggregationInputSchema: z.ZodType<Prisma.DocumentSignerOrderByWithAggregationInput> = z.object({
  id: z.lazy(() => SortOrderSchema).optional(),
  documentId: z.lazy(() => SortOrderSchema).optional(),
  email: z.lazy(() => SortOrderSchema).optional(),
  name: z.union([ z.lazy(() => SortOrderSchema),z.lazy(() => SortOrderInputSchema) ]).optional(),
  order: z.lazy(() => SortOrderSchema).optional(),
  status: z.lazy(() => SortOrderSchema).optional(),
  expiresAt: z.union([ z.lazy(() => SortOrderSchema),z.lazy(() => SortOrderInputSchema) ]).optional(),
  notifiedAt: z.union([ z.lazy(() => SortOrderSchema),z.lazy(() => SortOrderInputSchema) ]).optional(),
  createdAt: z.lazy(() => SortOrderSchema).optional(),
  updatedAt: z.lazy(() => SortOrderSchema).optional(),
  signatureId: z.union([ z.lazy(() => SortOrderSchema),z.lazy(() => SortOrderInputSchema) ]).optional(),
  _count: z.lazy(() => DocumentSignerCountOrderByAggregateInputSchema).optional(),
  _avg: z.lazy(() => DocumentSignerAvgOrderByAggregateInputSchema).optional(),
  _max: z.lazy(() => DocumentSignerMaxOrderByAggregateInputSchema).optional(),
  _min: z.lazy(() => DocumentSignerMinOrderByAggregateInputSchema).optional(),
  _sum: z.lazy(() => DocumentSignerSumOrderByAggregateInputSchema).optional()
}).strict();

export const DocumentSignerScalarWhereWithAggregatesInputSchema: z.ZodType<Prisma.DocumentSignerScalarWhereWithAggregatesInput> = z.object({
  AND: z.union([ z.lazy(() => DocumentSignerScalarWhereWithAggregatesInputSchema),z.lazy(() => DocumentSignerScalarWhereWithAggregatesInputSchema).array() ]).optional(),
  OR: z.lazy(() => DocumentSignerScalarWhereWithAggregatesInputSchema).array().optional(),
  NOT: z.union([ z.lazy(() => DocumentSignerScalarWhereWithAggregatesInputSchema),z.lazy(() => DocumentSignerScalarWhereWithAggregatesInputSchema).array() ]).optional(),
  id: z.union([ z.lazy(() => StringWithAggregatesFilterSchema),z.string() ]).optional(),
  documentId: z.union([ z.lazy(() => StringWithAggregatesFilterSchema),z.string() ]).optional(),
  email: z.union([ z.lazy(() => StringWithAggregatesFilterSchema),z.string() ]).optional(),
  name: z.union([ z.lazy(() => StringNullableWithAggregatesFilterSchema),z.string() ]).optional().nullable(),
  order: z.union([ z.lazy(() => IntWithAggregatesFilterSchema),z.number() ]).optional(),
  status: z.union([ z.lazy(() => EnumSignerStatusWithAggregatesFilterSchema),z.lazy(() => SignerStatusSchema) ]).optional(),
  expiresAt: z.union([ z.lazy(() => DateTimeNullableWithAggregatesFilterSchema),z.coerce.date() ]).optional().nullable(),
  notifiedAt: z.union([ z.lazy(() => DateTimeNullableWithAggregatesFilterSchema),z.coerce.date() ]).optional().nullable(),
  createdAt: z.union([ z.lazy(() => DateTimeWithAggregatesFilterSchema),z.coerce.date() ]).optional(),
  updatedAt: z.union([ z.lazy(() => DateTimeWithAggregatesFilterSchema),z.coerce.date() ]).optional(),
  signatureId: z.union([ z.lazy(() => StringNullableWithAggregatesFilterSchema),z.string() ]).optional().nullable(),
}).strict();

export const SignatureFieldWhereInputSchema: z.ZodType<Prisma.SignatureFieldWhereInput> = z.object({
  AND: z.union([ z.lazy(() => SignatureFieldWhereInputSchema),z.lazy(() => SignatureFieldWhereInputSchema).array() ]).optional(),
  OR: z.lazy(() => SignatureFieldWhereInputSchema).array().optional(),
  NOT: z.union([ z.lazy(() => SignatureFieldWhereInputSchema),z.lazy(() => SignatureFieldWhereInputSchema).array() ]).optional(),
  id: z.union([ z.lazy(() => StringFilterSchema),z.string() ]).optional(),
  documentId: z.union([ z.lazy(() => StringFilterSchema),z.string() ]).optional(),
  signerId: z.union([ z.lazy(() => StringFilterSchema),z.string() ]).optional(),
  type: z.union([ z.lazy(() => EnumFieldTypeFilterSchema),z.lazy(() => FieldTypeSchema) ]).optional(),
  required: z.union([ z.lazy(() => BoolFilterSchema),z.boolean() ]).optional(),
  page: z.union([ z.lazy(() => IntFilterSchema),z.number() ]).optional(),
  x: z.union([ z.lazy(() => FloatFilterSchema),z.number() ]).optional(),
  y: z.union([ z.lazy(() => FloatFilterSchema),z.number() ]).optional(),
  width: z.union([ z.lazy(() => FloatFilterSchema),z.number() ]).optional(),
  height: z.union([ z.lazy(() => FloatFilterSchema),z.number() ]).optional(),
  signedAt: z.union([ z.lazy(() => DateTimeNullableFilterSchema),z.coerce.date() ]).optional().nullable(),
  createdAt: z.union([ z.lazy(() => DateTimeFilterSchema),z.coerce.date() ]).optional(),
  updatedAt: z.union([ z.lazy(() => DateTimeFilterSchema),z.coerce.date() ]).optional(),
  document: z.union([ z.lazy(() => DocumentScalarRelationFilterSchema),z.lazy(() => DocumentWhereInputSchema) ]).optional(),
  signer: z.union([ z.lazy(() => DocumentSignerScalarRelationFilterSchema),z.lazy(() => DocumentSignerWhereInputSchema) ]).optional(),
}).strict();

export const SignatureFieldOrderByWithRelationInputSchema: z.ZodType<Prisma.SignatureFieldOrderByWithRelationInput> = z.object({
  id: z.lazy(() => SortOrderSchema).optional(),
  documentId: z.lazy(() => SortOrderSchema).optional(),
  signerId: z.lazy(() => SortOrderSchema).optional(),
  type: z.lazy(() => SortOrderSchema).optional(),
  required: z.lazy(() => SortOrderSchema).optional(),
  page: z.lazy(() => SortOrderSchema).optional(),
  x: z.lazy(() => SortOrderSchema).optional(),
  y: z.lazy(() => SortOrderSchema).optional(),
  width: z.lazy(() => SortOrderSchema).optional(),
  height: z.lazy(() => SortOrderSchema).optional(),
  signedAt: z.union([ z.lazy(() => SortOrderSchema),z.lazy(() => SortOrderInputSchema) ]).optional(),
  createdAt: z.lazy(() => SortOrderSchema).optional(),
  updatedAt: z.lazy(() => SortOrderSchema).optional(),
  document: z.lazy(() => DocumentOrderByWithRelationInputSchema).optional(),
  signer: z.lazy(() => DocumentSignerOrderByWithRelationInputSchema).optional()
}).strict();

export const SignatureFieldWhereUniqueInputSchema: z.ZodType<Prisma.SignatureFieldWhereUniqueInput> = z.object({
  id: z.string().uuid()
})
.and(z.object({
  id: z.string().uuid().optional(),
  AND: z.union([ z.lazy(() => SignatureFieldWhereInputSchema),z.lazy(() => SignatureFieldWhereInputSchema).array() ]).optional(),
  OR: z.lazy(() => SignatureFieldWhereInputSchema).array().optional(),
  NOT: z.union([ z.lazy(() => SignatureFieldWhereInputSchema),z.lazy(() => SignatureFieldWhereInputSchema).array() ]).optional(),
  documentId: z.union([ z.lazy(() => StringFilterSchema),z.string() ]).optional(),
  signerId: z.union([ z.lazy(() => StringFilterSchema),z.string() ]).optional(),
  type: z.union([ z.lazy(() => EnumFieldTypeFilterSchema),z.lazy(() => FieldTypeSchema) ]).optional(),
  required: z.union([ z.lazy(() => BoolFilterSchema),z.boolean() ]).optional(),
  page: z.union([ z.lazy(() => IntFilterSchema),z.number().int() ]).optional(),
  x: z.union([ z.lazy(() => FloatFilterSchema),z.number() ]).optional(),
  y: z.union([ z.lazy(() => FloatFilterSchema),z.number() ]).optional(),
  width: z.union([ z.lazy(() => FloatFilterSchema),z.number() ]).optional(),
  height: z.union([ z.lazy(() => FloatFilterSchema),z.number() ]).optional(),
  signedAt: z.union([ z.lazy(() => DateTimeNullableFilterSchema),z.coerce.date() ]).optional().nullable(),
  createdAt: z.union([ z.lazy(() => DateTimeFilterSchema),z.coerce.date() ]).optional(),
  updatedAt: z.union([ z.lazy(() => DateTimeFilterSchema),z.coerce.date() ]).optional(),
  document: z.union([ z.lazy(() => DocumentScalarRelationFilterSchema),z.lazy(() => DocumentWhereInputSchema) ]).optional(),
  signer: z.union([ z.lazy(() => DocumentSignerScalarRelationFilterSchema),z.lazy(() => DocumentSignerWhereInputSchema) ]).optional(),
}).strict());

export const SignatureFieldOrderByWithAggregationInputSchema: z.ZodType<Prisma.SignatureFieldOrderByWithAggregationInput> = z.object({
  id: z.lazy(() => SortOrderSchema).optional(),
  documentId: z.lazy(() => SortOrderSchema).optional(),
  signerId: z.lazy(() => SortOrderSchema).optional(),
  type: z.lazy(() => SortOrderSchema).optional(),
  required: z.lazy(() => SortOrderSchema).optional(),
  page: z.lazy(() => SortOrderSchema).optional(),
  x: z.lazy(() => SortOrderSchema).optional(),
  y: z.lazy(() => SortOrderSchema).optional(),
  width: z.lazy(() => SortOrderSchema).optional(),
  height: z.lazy(() => SortOrderSchema).optional(),
  signedAt: z.union([ z.lazy(() => SortOrderSchema),z.lazy(() => SortOrderInputSchema) ]).optional(),
  createdAt: z.lazy(() => SortOrderSchema).optional(),
  updatedAt: z.lazy(() => SortOrderSchema).optional(),
  _count: z.lazy(() => SignatureFieldCountOrderByAggregateInputSchema).optional(),
  _avg: z.lazy(() => SignatureFieldAvgOrderByAggregateInputSchema).optional(),
  _max: z.lazy(() => SignatureFieldMaxOrderByAggregateInputSchema).optional(),
  _min: z.lazy(() => SignatureFieldMinOrderByAggregateInputSchema).optional(),
  _sum: z.lazy(() => SignatureFieldSumOrderByAggregateInputSchema).optional()
}).strict();

export const SignatureFieldScalarWhereWithAggregatesInputSchema: z.ZodType<Prisma.SignatureFieldScalarWhereWithAggregatesInput> = z.object({
  AND: z.union([ z.lazy(() => SignatureFieldScalarWhereWithAggregatesInputSchema),z.lazy(() => SignatureFieldScalarWhereWithAggregatesInputSchema).array() ]).optional(),
  OR: z.lazy(() => SignatureFieldScalarWhereWithAggregatesInputSchema).array().optional(),
  NOT: z.union([ z.lazy(() => SignatureFieldScalarWhereWithAggregatesInputSchema),z.lazy(() => SignatureFieldScalarWhereWithAggregatesInputSchema).array() ]).optional(),
  id: z.union([ z.lazy(() => StringWithAggregatesFilterSchema),z.string() ]).optional(),
  documentId: z.union([ z.lazy(() => StringWithAggregatesFilterSchema),z.string() ]).optional(),
  signerId: z.union([ z.lazy(() => StringWithAggregatesFilterSchema),z.string() ]).optional(),
  type: z.union([ z.lazy(() => EnumFieldTypeWithAggregatesFilterSchema),z.lazy(() => FieldTypeSchema) ]).optional(),
  required: z.union([ z.lazy(() => BoolWithAggregatesFilterSchema),z.boolean() ]).optional(),
  page: z.union([ z.lazy(() => IntWithAggregatesFilterSchema),z.number() ]).optional(),
  x: z.union([ z.lazy(() => FloatWithAggregatesFilterSchema),z.number() ]).optional(),
  y: z.union([ z.lazy(() => FloatWithAggregatesFilterSchema),z.number() ]).optional(),
  width: z.union([ z.lazy(() => FloatWithAggregatesFilterSchema),z.number() ]).optional(),
  height: z.union([ z.lazy(() => FloatWithAggregatesFilterSchema),z.number() ]).optional(),
  signedAt: z.union([ z.lazy(() => DateTimeNullableWithAggregatesFilterSchema),z.coerce.date() ]).optional().nullable(),
  createdAt: z.union([ z.lazy(() => DateTimeWithAggregatesFilterSchema),z.coerce.date() ]).optional(),
  updatedAt: z.union([ z.lazy(() => DateTimeWithAggregatesFilterSchema),z.coerce.date() ]).optional(),
}).strict();

export const SignatureWhereInputSchema: z.ZodType<Prisma.SignatureWhereInput> = z.object({
  AND: z.union([ z.lazy(() => SignatureWhereInputSchema),z.lazy(() => SignatureWhereInputSchema).array() ]).optional(),
  OR: z.lazy(() => SignatureWhereInputSchema).array().optional(),
  NOT: z.union([ z.lazy(() => SignatureWhereInputSchema),z.lazy(() => SignatureWhereInputSchema).array() ]).optional(),
  id: z.union([ z.lazy(() => StringFilterSchema),z.string() ]).optional(),
  documentId: z.union([ z.lazy(() => StringFilterSchema),z.string() ]).optional(),
  userId: z.union([ z.lazy(() => StringFilterSchema),z.string() ]).optional(),
  certificateId: z.union([ z.lazy(() => StringFilterSchema),z.string() ]).optional(),
  signatureData: z.union([ z.lazy(() => StringFilterSchema),z.string() ]).optional(),
  visualSignature: z.union([ z.lazy(() => StringNullableFilterSchema),z.string() ]).optional().nullable(),
  blockchainTx: z.union([ z.lazy(() => StringNullableFilterSchema),z.string() ]).optional().nullable(),
  coordinates: z.lazy(() => JsonNullableFilterSchema).optional(),
  metadata: z.lazy(() => JsonNullableFilterSchema).optional(),
  createdAt: z.union([ z.lazy(() => DateTimeFilterSchema),z.coerce.date() ]).optional(),
  updatedAt: z.union([ z.lazy(() => DateTimeFilterSchema),z.coerce.date() ]).optional(),
  document: z.union([ z.lazy(() => DocumentScalarRelationFilterSchema),z.lazy(() => DocumentWhereInputSchema) ]).optional(),
  user: z.union([ z.lazy(() => UserScalarRelationFilterSchema),z.lazy(() => UserWhereInputSchema) ]).optional(),
  certificate: z.union([ z.lazy(() => CertificateScalarRelationFilterSchema),z.lazy(() => CertificateWhereInputSchema) ]).optional(),
  DocumentSigner: z.lazy(() => DocumentSignerListRelationFilterSchema).optional()
}).strict();

export const SignatureOrderByWithRelationInputSchema: z.ZodType<Prisma.SignatureOrderByWithRelationInput> = z.object({
  id: z.lazy(() => SortOrderSchema).optional(),
  documentId: z.lazy(() => SortOrderSchema).optional(),
  userId: z.lazy(() => SortOrderSchema).optional(),
  certificateId: z.lazy(() => SortOrderSchema).optional(),
  signatureData: z.lazy(() => SortOrderSchema).optional(),
  visualSignature: z.union([ z.lazy(() => SortOrderSchema),z.lazy(() => SortOrderInputSchema) ]).optional(),
  blockchainTx: z.union([ z.lazy(() => SortOrderSchema),z.lazy(() => SortOrderInputSchema) ]).optional(),
  coordinates: z.union([ z.lazy(() => SortOrderSchema),z.lazy(() => SortOrderInputSchema) ]).optional(),
  metadata: z.union([ z.lazy(() => SortOrderSchema),z.lazy(() => SortOrderInputSchema) ]).optional(),
  createdAt: z.lazy(() => SortOrderSchema).optional(),
  updatedAt: z.lazy(() => SortOrderSchema).optional(),
  document: z.lazy(() => DocumentOrderByWithRelationInputSchema).optional(),
  user: z.lazy(() => UserOrderByWithRelationInputSchema).optional(),
  certificate: z.lazy(() => CertificateOrderByWithRelationInputSchema).optional(),
  DocumentSigner: z.lazy(() => DocumentSignerOrderByRelationAggregateInputSchema).optional()
}).strict();

export const SignatureWhereUniqueInputSchema: z.ZodType<Prisma.SignatureWhereUniqueInput> = z.object({
  id: z.string().uuid()
})
.and(z.object({
  id: z.string().uuid().optional(),
  AND: z.union([ z.lazy(() => SignatureWhereInputSchema),z.lazy(() => SignatureWhereInputSchema).array() ]).optional(),
  OR: z.lazy(() => SignatureWhereInputSchema).array().optional(),
  NOT: z.union([ z.lazy(() => SignatureWhereInputSchema),z.lazy(() => SignatureWhereInputSchema).array() ]).optional(),
  documentId: z.union([ z.lazy(() => StringFilterSchema),z.string() ]).optional(),
  userId: z.union([ z.lazy(() => StringFilterSchema),z.string() ]).optional(),
  certificateId: z.union([ z.lazy(() => StringFilterSchema),z.string() ]).optional(),
  signatureData: z.union([ z.lazy(() => StringFilterSchema),z.string() ]).optional(),
  visualSignature: z.union([ z.lazy(() => StringNullableFilterSchema),z.string() ]).optional().nullable(),
  blockchainTx: z.union([ z.lazy(() => StringNullableFilterSchema),z.string() ]).optional().nullable(),
  coordinates: z.lazy(() => JsonNullableFilterSchema).optional(),
  metadata: z.lazy(() => JsonNullableFilterSchema).optional(),
  createdAt: z.union([ z.lazy(() => DateTimeFilterSchema),z.coerce.date() ]).optional(),
  updatedAt: z.union([ z.lazy(() => DateTimeFilterSchema),z.coerce.date() ]).optional(),
  document: z.union([ z.lazy(() => DocumentScalarRelationFilterSchema),z.lazy(() => DocumentWhereInputSchema) ]).optional(),
  user: z.union([ z.lazy(() => UserScalarRelationFilterSchema),z.lazy(() => UserWhereInputSchema) ]).optional(),
  certificate: z.union([ z.lazy(() => CertificateScalarRelationFilterSchema),z.lazy(() => CertificateWhereInputSchema) ]).optional(),
  DocumentSigner: z.lazy(() => DocumentSignerListRelationFilterSchema).optional()
}).strict());

export const SignatureOrderByWithAggregationInputSchema: z.ZodType<Prisma.SignatureOrderByWithAggregationInput> = z.object({
  id: z.lazy(() => SortOrderSchema).optional(),
  documentId: z.lazy(() => SortOrderSchema).optional(),
  userId: z.lazy(() => SortOrderSchema).optional(),
  certificateId: z.lazy(() => SortOrderSchema).optional(),
  signatureData: z.lazy(() => SortOrderSchema).optional(),
  visualSignature: z.union([ z.lazy(() => SortOrderSchema),z.lazy(() => SortOrderInputSchema) ]).optional(),
  blockchainTx: z.union([ z.lazy(() => SortOrderSchema),z.lazy(() => SortOrderInputSchema) ]).optional(),
  coordinates: z.union([ z.lazy(() => SortOrderSchema),z.lazy(() => SortOrderInputSchema) ]).optional(),
  metadata: z.union([ z.lazy(() => SortOrderSchema),z.lazy(() => SortOrderInputSchema) ]).optional(),
  createdAt: z.lazy(() => SortOrderSchema).optional(),
  updatedAt: z.lazy(() => SortOrderSchema).optional(),
  _count: z.lazy(() => SignatureCountOrderByAggregateInputSchema).optional(),
  _max: z.lazy(() => SignatureMaxOrderByAggregateInputSchema).optional(),
  _min: z.lazy(() => SignatureMinOrderByAggregateInputSchema).optional()
}).strict();

export const SignatureScalarWhereWithAggregatesInputSchema: z.ZodType<Prisma.SignatureScalarWhereWithAggregatesInput> = z.object({
  AND: z.union([ z.lazy(() => SignatureScalarWhereWithAggregatesInputSchema),z.lazy(() => SignatureScalarWhereWithAggregatesInputSchema).array() ]).optional(),
  OR: z.lazy(() => SignatureScalarWhereWithAggregatesInputSchema).array().optional(),
  NOT: z.union([ z.lazy(() => SignatureScalarWhereWithAggregatesInputSchema),z.lazy(() => SignatureScalarWhereWithAggregatesInputSchema).array() ]).optional(),
  id: z.union([ z.lazy(() => StringWithAggregatesFilterSchema),z.string() ]).optional(),
  documentId: z.union([ z.lazy(() => StringWithAggregatesFilterSchema),z.string() ]).optional(),
  userId: z.union([ z.lazy(() => StringWithAggregatesFilterSchema),z.string() ]).optional(),
  certificateId: z.union([ z.lazy(() => StringWithAggregatesFilterSchema),z.string() ]).optional(),
  signatureData: z.union([ z.lazy(() => StringWithAggregatesFilterSchema),z.string() ]).optional(),
  visualSignature: z.union([ z.lazy(() => StringNullableWithAggregatesFilterSchema),z.string() ]).optional().nullable(),
  blockchainTx: z.union([ z.lazy(() => StringNullableWithAggregatesFilterSchema),z.string() ]).optional().nullable(),
  coordinates: z.lazy(() => JsonNullableWithAggregatesFilterSchema).optional(),
  metadata: z.lazy(() => JsonNullableWithAggregatesFilterSchema).optional(),
  createdAt: z.union([ z.lazy(() => DateTimeWithAggregatesFilterSchema),z.coerce.date() ]).optional(),
  updatedAt: z.union([ z.lazy(() => DateTimeWithAggregatesFilterSchema),z.coerce.date() ]).optional(),
}).strict();

export const CertificateWhereInputSchema: z.ZodType<Prisma.CertificateWhereInput> = z.object({
  AND: z.union([ z.lazy(() => CertificateWhereInputSchema),z.lazy(() => CertificateWhereInputSchema).array() ]).optional(),
  OR: z.lazy(() => CertificateWhereInputSchema).array().optional(),
  NOT: z.union([ z.lazy(() => CertificateWhereInputSchema),z.lazy(() => CertificateWhereInputSchema).array() ]).optional(),
  id: z.union([ z.lazy(() => StringFilterSchema),z.string() ]).optional(),
  companyId: z.union([ z.lazy(() => IntFilterSchema),z.number() ]).optional(),
  fingerprint: z.union([ z.lazy(() => StringFilterSchema),z.string() ]).optional(),
  publicKey: z.union([ z.lazy(() => StringFilterSchema),z.string() ]).optional(),
  privateKey: z.union([ z.lazy(() => StringNullableFilterSchema),z.string() ]).optional().nullable(),
  isCA: z.union([ z.lazy(() => BoolFilterSchema),z.boolean() ]).optional(),
  issuerCertId: z.union([ z.lazy(() => StringNullableFilterSchema),z.string() ]).optional().nullable(),
  validFrom: z.union([ z.lazy(() => DateTimeFilterSchema),z.coerce.date() ]).optional(),
  validTo: z.union([ z.lazy(() => DateTimeFilterSchema),z.coerce.date() ]).optional(),
  metadata: z.lazy(() => JsonNullableFilterSchema).optional(),
  createdAt: z.union([ z.lazy(() => DateTimeFilterSchema),z.coerce.date() ]).optional(),
  updatedAt: z.union([ z.lazy(() => DateTimeFilterSchema),z.coerce.date() ]).optional(),
  company: z.union([ z.lazy(() => CompanyScalarRelationFilterSchema),z.lazy(() => CompanyWhereInputSchema) ]).optional(),
  signatures: z.lazy(() => SignatureListRelationFilterSchema).optional()
}).strict();

export const CertificateOrderByWithRelationInputSchema: z.ZodType<Prisma.CertificateOrderByWithRelationInput> = z.object({
  id: z.lazy(() => SortOrderSchema).optional(),
  companyId: z.lazy(() => SortOrderSchema).optional(),
  fingerprint: z.lazy(() => SortOrderSchema).optional(),
  publicKey: z.lazy(() => SortOrderSchema).optional(),
  privateKey: z.union([ z.lazy(() => SortOrderSchema),z.lazy(() => SortOrderInputSchema) ]).optional(),
  isCA: z.lazy(() => SortOrderSchema).optional(),
  issuerCertId: z.union([ z.lazy(() => SortOrderSchema),z.lazy(() => SortOrderInputSchema) ]).optional(),
  validFrom: z.lazy(() => SortOrderSchema).optional(),
  validTo: z.lazy(() => SortOrderSchema).optional(),
  metadata: z.union([ z.lazy(() => SortOrderSchema),z.lazy(() => SortOrderInputSchema) ]).optional(),
  createdAt: z.lazy(() => SortOrderSchema).optional(),
  updatedAt: z.lazy(() => SortOrderSchema).optional(),
  company: z.lazy(() => CompanyOrderByWithRelationInputSchema).optional(),
  signatures: z.lazy(() => SignatureOrderByRelationAggregateInputSchema).optional()
}).strict();

export const CertificateWhereUniqueInputSchema: z.ZodType<Prisma.CertificateWhereUniqueInput> = z.union([
  z.object({
    id: z.string().uuid(),
    fingerprint: z.string()
  }),
  z.object({
    id: z.string().uuid(),
  }),
  z.object({
    fingerprint: z.string(),
  }),
])
.and(z.object({
  id: z.string().uuid().optional(),
  fingerprint: z.string().optional(),
  AND: z.union([ z.lazy(() => CertificateWhereInputSchema),z.lazy(() => CertificateWhereInputSchema).array() ]).optional(),
  OR: z.lazy(() => CertificateWhereInputSchema).array().optional(),
  NOT: z.union([ z.lazy(() => CertificateWhereInputSchema),z.lazy(() => CertificateWhereInputSchema).array() ]).optional(),
  companyId: z.union([ z.lazy(() => IntFilterSchema),z.number().int() ]).optional(),
  publicKey: z.union([ z.lazy(() => StringFilterSchema),z.string() ]).optional(),
  privateKey: z.union([ z.lazy(() => StringNullableFilterSchema),z.string() ]).optional().nullable(),
  isCA: z.union([ z.lazy(() => BoolFilterSchema),z.boolean() ]).optional(),
  issuerCertId: z.union([ z.lazy(() => StringNullableFilterSchema),z.string() ]).optional().nullable(),
  validFrom: z.union([ z.lazy(() => DateTimeFilterSchema),z.coerce.date() ]).optional(),
  validTo: z.union([ z.lazy(() => DateTimeFilterSchema),z.coerce.date() ]).optional(),
  metadata: z.lazy(() => JsonNullableFilterSchema).optional(),
  createdAt: z.union([ z.lazy(() => DateTimeFilterSchema),z.coerce.date() ]).optional(),
  updatedAt: z.union([ z.lazy(() => DateTimeFilterSchema),z.coerce.date() ]).optional(),
  company: z.union([ z.lazy(() => CompanyScalarRelationFilterSchema),z.lazy(() => CompanyWhereInputSchema) ]).optional(),
  signatures: z.lazy(() => SignatureListRelationFilterSchema).optional()
}).strict());

export const CertificateOrderByWithAggregationInputSchema: z.ZodType<Prisma.CertificateOrderByWithAggregationInput> = z.object({
  id: z.lazy(() => SortOrderSchema).optional(),
  companyId: z.lazy(() => SortOrderSchema).optional(),
  fingerprint: z.lazy(() => SortOrderSchema).optional(),
  publicKey: z.lazy(() => SortOrderSchema).optional(),
  privateKey: z.union([ z.lazy(() => SortOrderSchema),z.lazy(() => SortOrderInputSchema) ]).optional(),
  isCA: z.lazy(() => SortOrderSchema).optional(),
  issuerCertId: z.union([ z.lazy(() => SortOrderSchema),z.lazy(() => SortOrderInputSchema) ]).optional(),
  validFrom: z.lazy(() => SortOrderSchema).optional(),
  validTo: z.lazy(() => SortOrderSchema).optional(),
  metadata: z.union([ z.lazy(() => SortOrderSchema),z.lazy(() => SortOrderInputSchema) ]).optional(),
  createdAt: z.lazy(() => SortOrderSchema).optional(),
  updatedAt: z.lazy(() => SortOrderSchema).optional(),
  _count: z.lazy(() => CertificateCountOrderByAggregateInputSchema).optional(),
  _avg: z.lazy(() => CertificateAvgOrderByAggregateInputSchema).optional(),
  _max: z.lazy(() => CertificateMaxOrderByAggregateInputSchema).optional(),
  _min: z.lazy(() => CertificateMinOrderByAggregateInputSchema).optional(),
  _sum: z.lazy(() => CertificateSumOrderByAggregateInputSchema).optional()
}).strict();

export const CertificateScalarWhereWithAggregatesInputSchema: z.ZodType<Prisma.CertificateScalarWhereWithAggregatesInput> = z.object({
  AND: z.union([ z.lazy(() => CertificateScalarWhereWithAggregatesInputSchema),z.lazy(() => CertificateScalarWhereWithAggregatesInputSchema).array() ]).optional(),
  OR: z.lazy(() => CertificateScalarWhereWithAggregatesInputSchema).array().optional(),
  NOT: z.union([ z.lazy(() => CertificateScalarWhereWithAggregatesInputSchema),z.lazy(() => CertificateScalarWhereWithAggregatesInputSchema).array() ]).optional(),
  id: z.union([ z.lazy(() => StringWithAggregatesFilterSchema),z.string() ]).optional(),
  companyId: z.union([ z.lazy(() => IntWithAggregatesFilterSchema),z.number() ]).optional(),
  fingerprint: z.union([ z.lazy(() => StringWithAggregatesFilterSchema),z.string() ]).optional(),
  publicKey: z.union([ z.lazy(() => StringWithAggregatesFilterSchema),z.string() ]).optional(),
  privateKey: z.union([ z.lazy(() => StringNullableWithAggregatesFilterSchema),z.string() ]).optional().nullable(),
  isCA: z.union([ z.lazy(() => BoolWithAggregatesFilterSchema),z.boolean() ]).optional(),
  issuerCertId: z.union([ z.lazy(() => StringNullableWithAggregatesFilterSchema),z.string() ]).optional().nullable(),
  validFrom: z.union([ z.lazy(() => DateTimeWithAggregatesFilterSchema),z.coerce.date() ]).optional(),
  validTo: z.union([ z.lazy(() => DateTimeWithAggregatesFilterSchema),z.coerce.date() ]).optional(),
  metadata: z.lazy(() => JsonNullableWithAggregatesFilterSchema).optional(),
  createdAt: z.union([ z.lazy(() => DateTimeWithAggregatesFilterSchema),z.coerce.date() ]).optional(),
  updatedAt: z.union([ z.lazy(() => DateTimeWithAggregatesFilterSchema),z.coerce.date() ]).optional(),
}).strict();

export const SigningTemplateWhereInputSchema: z.ZodType<Prisma.SigningTemplateWhereInput> = z.object({
  AND: z.union([ z.lazy(() => SigningTemplateWhereInputSchema),z.lazy(() => SigningTemplateWhereInputSchema).array() ]).optional(),
  OR: z.lazy(() => SigningTemplateWhereInputSchema).array().optional(),
  NOT: z.union([ z.lazy(() => SigningTemplateWhereInputSchema),z.lazy(() => SigningTemplateWhereInputSchema).array() ]).optional(),
  id: z.union([ z.lazy(() => StringFilterSchema),z.string() ]).optional(),
  name: z.union([ z.lazy(() => StringFilterSchema),z.string() ]).optional(),
  companyId: z.union([ z.lazy(() => IntFilterSchema),z.number() ]).optional(),
  fields: z.lazy(() => JsonFilterSchema).optional(),
  createdAt: z.union([ z.lazy(() => DateTimeFilterSchema),z.coerce.date() ]).optional(),
  updatedAt: z.union([ z.lazy(() => DateTimeFilterSchema),z.coerce.date() ]).optional(),
  company: z.union([ z.lazy(() => CompanyScalarRelationFilterSchema),z.lazy(() => CompanyWhereInputSchema) ]).optional(),
  documents: z.lazy(() => DocumentListRelationFilterSchema).optional()
}).strict();

export const SigningTemplateOrderByWithRelationInputSchema: z.ZodType<Prisma.SigningTemplateOrderByWithRelationInput> = z.object({
  id: z.lazy(() => SortOrderSchema).optional(),
  name: z.lazy(() => SortOrderSchema).optional(),
  companyId: z.lazy(() => SortOrderSchema).optional(),
  fields: z.lazy(() => SortOrderSchema).optional(),
  createdAt: z.lazy(() => SortOrderSchema).optional(),
  updatedAt: z.lazy(() => SortOrderSchema).optional(),
  company: z.lazy(() => CompanyOrderByWithRelationInputSchema).optional(),
  documents: z.lazy(() => DocumentOrderByRelationAggregateInputSchema).optional()
}).strict();

export const SigningTemplateWhereUniqueInputSchema: z.ZodType<Prisma.SigningTemplateWhereUniqueInput> = z.object({
  id: z.string().uuid()
})
.and(z.object({
  id: z.string().uuid().optional(),
  AND: z.union([ z.lazy(() => SigningTemplateWhereInputSchema),z.lazy(() => SigningTemplateWhereInputSchema).array() ]).optional(),
  OR: z.lazy(() => SigningTemplateWhereInputSchema).array().optional(),
  NOT: z.union([ z.lazy(() => SigningTemplateWhereInputSchema),z.lazy(() => SigningTemplateWhereInputSchema).array() ]).optional(),
  name: z.union([ z.lazy(() => StringFilterSchema),z.string() ]).optional(),
  companyId: z.union([ z.lazy(() => IntFilterSchema),z.number().int() ]).optional(),
  fields: z.lazy(() => JsonFilterSchema).optional(),
  createdAt: z.union([ z.lazy(() => DateTimeFilterSchema),z.coerce.date() ]).optional(),
  updatedAt: z.union([ z.lazy(() => DateTimeFilterSchema),z.coerce.date() ]).optional(),
  company: z.union([ z.lazy(() => CompanyScalarRelationFilterSchema),z.lazy(() => CompanyWhereInputSchema) ]).optional(),
  documents: z.lazy(() => DocumentListRelationFilterSchema).optional()
}).strict());

export const SigningTemplateOrderByWithAggregationInputSchema: z.ZodType<Prisma.SigningTemplateOrderByWithAggregationInput> = z.object({
  id: z.lazy(() => SortOrderSchema).optional(),
  name: z.lazy(() => SortOrderSchema).optional(),
  companyId: z.lazy(() => SortOrderSchema).optional(),
  fields: z.lazy(() => SortOrderSchema).optional(),
  createdAt: z.lazy(() => SortOrderSchema).optional(),
  updatedAt: z.lazy(() => SortOrderSchema).optional(),
  _count: z.lazy(() => SigningTemplateCountOrderByAggregateInputSchema).optional(),
  _avg: z.lazy(() => SigningTemplateAvgOrderByAggregateInputSchema).optional(),
  _max: z.lazy(() => SigningTemplateMaxOrderByAggregateInputSchema).optional(),
  _min: z.lazy(() => SigningTemplateMinOrderByAggregateInputSchema).optional(),
  _sum: z.lazy(() => SigningTemplateSumOrderByAggregateInputSchema).optional()
}).strict();

export const SigningTemplateScalarWhereWithAggregatesInputSchema: z.ZodType<Prisma.SigningTemplateScalarWhereWithAggregatesInput> = z.object({
  AND: z.union([ z.lazy(() => SigningTemplateScalarWhereWithAggregatesInputSchema),z.lazy(() => SigningTemplateScalarWhereWithAggregatesInputSchema).array() ]).optional(),
  OR: z.lazy(() => SigningTemplateScalarWhereWithAggregatesInputSchema).array().optional(),
  NOT: z.union([ z.lazy(() => SigningTemplateScalarWhereWithAggregatesInputSchema),z.lazy(() => SigningTemplateScalarWhereWithAggregatesInputSchema).array() ]).optional(),
  id: z.union([ z.lazy(() => StringWithAggregatesFilterSchema),z.string() ]).optional(),
  name: z.union([ z.lazy(() => StringWithAggregatesFilterSchema),z.string() ]).optional(),
  companyId: z.union([ z.lazy(() => IntWithAggregatesFilterSchema),z.number() ]).optional(),
  fields: z.lazy(() => JsonWithAggregatesFilterSchema).optional(),
  createdAt: z.union([ z.lazy(() => DateTimeWithAggregatesFilterSchema),z.coerce.date() ]).optional(),
  updatedAt: z.union([ z.lazy(() => DateTimeWithAggregatesFilterSchema),z.coerce.date() ]).optional(),
}).strict();

export const BlockchainWalletWhereInputSchema: z.ZodType<Prisma.BlockchainWalletWhereInput> = z.object({
  AND: z.union([ z.lazy(() => BlockchainWalletWhereInputSchema),z.lazy(() => BlockchainWalletWhereInputSchema).array() ]).optional(),
  OR: z.lazy(() => BlockchainWalletWhereInputSchema).array().optional(),
  NOT: z.union([ z.lazy(() => BlockchainWalletWhereInputSchema),z.lazy(() => BlockchainWalletWhereInputSchema).array() ]).optional(),
  id: z.union([ z.lazy(() => StringFilterSchema),z.string() ]).optional(),
  companyId: z.union([ z.lazy(() => IntFilterSchema),z.number() ]).optional(),
  address: z.union([ z.lazy(() => StringFilterSchema),z.string() ]).optional(),
  privateKey: z.union([ z.lazy(() => StringNullableFilterSchema),z.string() ]).optional().nullable(),
  createdAt: z.union([ z.lazy(() => DateTimeFilterSchema),z.coerce.date() ]).optional(),
  updatedAt: z.union([ z.lazy(() => DateTimeFilterSchema),z.coerce.date() ]).optional(),
  company: z.union([ z.lazy(() => CompanyScalarRelationFilterSchema),z.lazy(() => CompanyWhereInputSchema) ]).optional(),
}).strict();

export const BlockchainWalletOrderByWithRelationInputSchema: z.ZodType<Prisma.BlockchainWalletOrderByWithRelationInput> = z.object({
  id: z.lazy(() => SortOrderSchema).optional(),
  companyId: z.lazy(() => SortOrderSchema).optional(),
  address: z.lazy(() => SortOrderSchema).optional(),
  privateKey: z.union([ z.lazy(() => SortOrderSchema),z.lazy(() => SortOrderInputSchema) ]).optional(),
  createdAt: z.lazy(() => SortOrderSchema).optional(),
  updatedAt: z.lazy(() => SortOrderSchema).optional(),
  company: z.lazy(() => CompanyOrderByWithRelationInputSchema).optional()
}).strict();

export const BlockchainWalletWhereUniqueInputSchema: z.ZodType<Prisma.BlockchainWalletWhereUniqueInput> = z.union([
  z.object({
    id: z.string().uuid(),
    companyId: z.number().int(),
    address: z.string()
  }),
  z.object({
    id: z.string().uuid(),
    companyId: z.number().int(),
  }),
  z.object({
    id: z.string().uuid(),
    address: z.string(),
  }),
  z.object({
    id: z.string().uuid(),
  }),
  z.object({
    companyId: z.number().int(),
    address: z.string(),
  }),
  z.object({
    companyId: z.number().int(),
  }),
  z.object({
    address: z.string(),
  }),
])
.and(z.object({
  id: z.string().uuid().optional(),
  companyId: z.number().int().optional(),
  address: z.string().optional(),
  AND: z.union([ z.lazy(() => BlockchainWalletWhereInputSchema),z.lazy(() => BlockchainWalletWhereInputSchema).array() ]).optional(),
  OR: z.lazy(() => BlockchainWalletWhereInputSchema).array().optional(),
  NOT: z.union([ z.lazy(() => BlockchainWalletWhereInputSchema),z.lazy(() => BlockchainWalletWhereInputSchema).array() ]).optional(),
  privateKey: z.union([ z.lazy(() => StringNullableFilterSchema),z.string() ]).optional().nullable(),
  createdAt: z.union([ z.lazy(() => DateTimeFilterSchema),z.coerce.date() ]).optional(),
  updatedAt: z.union([ z.lazy(() => DateTimeFilterSchema),z.coerce.date() ]).optional(),
  company: z.union([ z.lazy(() => CompanyScalarRelationFilterSchema),z.lazy(() => CompanyWhereInputSchema) ]).optional(),
}).strict());

export const BlockchainWalletOrderByWithAggregationInputSchema: z.ZodType<Prisma.BlockchainWalletOrderByWithAggregationInput> = z.object({
  id: z.lazy(() => SortOrderSchema).optional(),
  companyId: z.lazy(() => SortOrderSchema).optional(),
  address: z.lazy(() => SortOrderSchema).optional(),
  privateKey: z.union([ z.lazy(() => SortOrderSchema),z.lazy(() => SortOrderInputSchema) ]).optional(),
  createdAt: z.lazy(() => SortOrderSchema).optional(),
  updatedAt: z.lazy(() => SortOrderSchema).optional(),
  _count: z.lazy(() => BlockchainWalletCountOrderByAggregateInputSchema).optional(),
  _avg: z.lazy(() => BlockchainWalletAvgOrderByAggregateInputSchema).optional(),
  _max: z.lazy(() => BlockchainWalletMaxOrderByAggregateInputSchema).optional(),
  _min: z.lazy(() => BlockchainWalletMinOrderByAggregateInputSchema).optional(),
  _sum: z.lazy(() => BlockchainWalletSumOrderByAggregateInputSchema).optional()
}).strict();

export const BlockchainWalletScalarWhereWithAggregatesInputSchema: z.ZodType<Prisma.BlockchainWalletScalarWhereWithAggregatesInput> = z.object({
  AND: z.union([ z.lazy(() => BlockchainWalletScalarWhereWithAggregatesInputSchema),z.lazy(() => BlockchainWalletScalarWhereWithAggregatesInputSchema).array() ]).optional(),
  OR: z.lazy(() => BlockchainWalletScalarWhereWithAggregatesInputSchema).array().optional(),
  NOT: z.union([ z.lazy(() => BlockchainWalletScalarWhereWithAggregatesInputSchema),z.lazy(() => BlockchainWalletScalarWhereWithAggregatesInputSchema).array() ]).optional(),
  id: z.union([ z.lazy(() => StringWithAggregatesFilterSchema),z.string() ]).optional(),
  companyId: z.union([ z.lazy(() => IntWithAggregatesFilterSchema),z.number() ]).optional(),
  address: z.union([ z.lazy(() => StringWithAggregatesFilterSchema),z.string() ]).optional(),
  privateKey: z.union([ z.lazy(() => StringNullableWithAggregatesFilterSchema),z.string() ]).optional().nullable(),
  createdAt: z.union([ z.lazy(() => DateTimeWithAggregatesFilterSchema),z.coerce.date() ]).optional(),
  updatedAt: z.union([ z.lazy(() => DateTimeWithAggregatesFilterSchema),z.coerce.date() ]).optional(),
}).strict();

export const ApiKeyWhereInputSchema: z.ZodType<Prisma.ApiKeyWhereInput> = z.object({
  AND: z.union([ z.lazy(() => ApiKeyWhereInputSchema),z.lazy(() => ApiKeyWhereInputSchema).array() ]).optional(),
  OR: z.lazy(() => ApiKeyWhereInputSchema).array().optional(),
  NOT: z.union([ z.lazy(() => ApiKeyWhereInputSchema),z.lazy(() => ApiKeyWhereInputSchema).array() ]).optional(),
  id: z.union([ z.lazy(() => StringFilterSchema),z.string() ]).optional(),
  companyId: z.union([ z.lazy(() => IntFilterSchema),z.number() ]).optional(),
  key: z.union([ z.lazy(() => StringFilterSchema),z.string() ]).optional(),
  createdAt: z.union([ z.lazy(() => DateTimeFilterSchema),z.coerce.date() ]).optional(),
  updatedAt: z.union([ z.lazy(() => DateTimeFilterSchema),z.coerce.date() ]).optional(),
  isActive: z.union([ z.lazy(() => BoolFilterSchema),z.boolean() ]).optional(),
  isDeleted: z.union([ z.lazy(() => BoolFilterSchema),z.boolean() ]).optional(),
  isRevoked: z.union([ z.lazy(() => BoolFilterSchema),z.boolean() ]).optional(),
  lastUsed: z.union([ z.lazy(() => DateTimeNullableFilterSchema),z.coerce.date() ]).optional().nullable(),
  company: z.union([ z.lazy(() => CompanyScalarRelationFilterSchema),z.lazy(() => CompanyWhereInputSchema) ]).optional(),
  user: z.lazy(() => UserListRelationFilterSchema).optional()
}).strict();

export const ApiKeyOrderByWithRelationInputSchema: z.ZodType<Prisma.ApiKeyOrderByWithRelationInput> = z.object({
  id: z.lazy(() => SortOrderSchema).optional(),
  companyId: z.lazy(() => SortOrderSchema).optional(),
  key: z.lazy(() => SortOrderSchema).optional(),
  createdAt: z.lazy(() => SortOrderSchema).optional(),
  updatedAt: z.lazy(() => SortOrderSchema).optional(),
  isActive: z.lazy(() => SortOrderSchema).optional(),
  isDeleted: z.lazy(() => SortOrderSchema).optional(),
  isRevoked: z.lazy(() => SortOrderSchema).optional(),
  lastUsed: z.union([ z.lazy(() => SortOrderSchema),z.lazy(() => SortOrderInputSchema) ]).optional(),
  company: z.lazy(() => CompanyOrderByWithRelationInputSchema).optional(),
  user: z.lazy(() => UserOrderByRelationAggregateInputSchema).optional()
}).strict();

export const ApiKeyWhereUniqueInputSchema: z.ZodType<Prisma.ApiKeyWhereUniqueInput> = z.union([
  z.object({
    id: z.string().uuid(),
    key: z.string()
  }),
  z.object({
    id: z.string().uuid(),
  }),
  z.object({
    key: z.string(),
  }),
])
.and(z.object({
  id: z.string().uuid().optional(),
  key: z.string().optional(),
  AND: z.union([ z.lazy(() => ApiKeyWhereInputSchema),z.lazy(() => ApiKeyWhereInputSchema).array() ]).optional(),
  OR: z.lazy(() => ApiKeyWhereInputSchema).array().optional(),
  NOT: z.union([ z.lazy(() => ApiKeyWhereInputSchema),z.lazy(() => ApiKeyWhereInputSchema).array() ]).optional(),
  companyId: z.union([ z.lazy(() => IntFilterSchema),z.number().int() ]).optional(),
  createdAt: z.union([ z.lazy(() => DateTimeFilterSchema),z.coerce.date() ]).optional(),
  updatedAt: z.union([ z.lazy(() => DateTimeFilterSchema),z.coerce.date() ]).optional(),
  isActive: z.union([ z.lazy(() => BoolFilterSchema),z.boolean() ]).optional(),
  isDeleted: z.union([ z.lazy(() => BoolFilterSchema),z.boolean() ]).optional(),
  isRevoked: z.union([ z.lazy(() => BoolFilterSchema),z.boolean() ]).optional(),
  lastUsed: z.union([ z.lazy(() => DateTimeNullableFilterSchema),z.coerce.date() ]).optional().nullable(),
  company: z.union([ z.lazy(() => CompanyScalarRelationFilterSchema),z.lazy(() => CompanyWhereInputSchema) ]).optional(),
  user: z.lazy(() => UserListRelationFilterSchema).optional()
}).strict());

export const ApiKeyOrderByWithAggregationInputSchema: z.ZodType<Prisma.ApiKeyOrderByWithAggregationInput> = z.object({
  id: z.lazy(() => SortOrderSchema).optional(),
  companyId: z.lazy(() => SortOrderSchema).optional(),
  key: z.lazy(() => SortOrderSchema).optional(),
  createdAt: z.lazy(() => SortOrderSchema).optional(),
  updatedAt: z.lazy(() => SortOrderSchema).optional(),
  isActive: z.lazy(() => SortOrderSchema).optional(),
  isDeleted: z.lazy(() => SortOrderSchema).optional(),
  isRevoked: z.lazy(() => SortOrderSchema).optional(),
  lastUsed: z.union([ z.lazy(() => SortOrderSchema),z.lazy(() => SortOrderInputSchema) ]).optional(),
  _count: z.lazy(() => ApiKeyCountOrderByAggregateInputSchema).optional(),
  _avg: z.lazy(() => ApiKeyAvgOrderByAggregateInputSchema).optional(),
  _max: z.lazy(() => ApiKeyMaxOrderByAggregateInputSchema).optional(),
  _min: z.lazy(() => ApiKeyMinOrderByAggregateInputSchema).optional(),
  _sum: z.lazy(() => ApiKeySumOrderByAggregateInputSchema).optional()
}).strict();

export const ApiKeyScalarWhereWithAggregatesInputSchema: z.ZodType<Prisma.ApiKeyScalarWhereWithAggregatesInput> = z.object({
  AND: z.union([ z.lazy(() => ApiKeyScalarWhereWithAggregatesInputSchema),z.lazy(() => ApiKeyScalarWhereWithAggregatesInputSchema).array() ]).optional(),
  OR: z.lazy(() => ApiKeyScalarWhereWithAggregatesInputSchema).array().optional(),
  NOT: z.union([ z.lazy(() => ApiKeyScalarWhereWithAggregatesInputSchema),z.lazy(() => ApiKeyScalarWhereWithAggregatesInputSchema).array() ]).optional(),
  id: z.union([ z.lazy(() => StringWithAggregatesFilterSchema),z.string() ]).optional(),
  companyId: z.union([ z.lazy(() => IntWithAggregatesFilterSchema),z.number() ]).optional(),
  key: z.union([ z.lazy(() => StringWithAggregatesFilterSchema),z.string() ]).optional(),
  createdAt: z.union([ z.lazy(() => DateTimeWithAggregatesFilterSchema),z.coerce.date() ]).optional(),
  updatedAt: z.union([ z.lazy(() => DateTimeWithAggregatesFilterSchema),z.coerce.date() ]).optional(),
  isActive: z.union([ z.lazy(() => BoolWithAggregatesFilterSchema),z.boolean() ]).optional(),
  isDeleted: z.union([ z.lazy(() => BoolWithAggregatesFilterSchema),z.boolean() ]).optional(),
  isRevoked: z.union([ z.lazy(() => BoolWithAggregatesFilterSchema),z.boolean() ]).optional(),
  lastUsed: z.union([ z.lazy(() => DateTimeNullableWithAggregatesFilterSchema),z.coerce.date() ]).optional().nullable(),
}).strict();

export const AuditLogWhereInputSchema: z.ZodType<Prisma.AuditLogWhereInput> = z.object({
  AND: z.union([ z.lazy(() => AuditLogWhereInputSchema),z.lazy(() => AuditLogWhereInputSchema).array() ]).optional(),
  OR: z.lazy(() => AuditLogWhereInputSchema).array().optional(),
  NOT: z.union([ z.lazy(() => AuditLogWhereInputSchema),z.lazy(() => AuditLogWhereInputSchema).array() ]).optional(),
  id: z.union([ z.lazy(() => StringFilterSchema),z.string() ]).optional(),
  documentId: z.union([ z.lazy(() => StringFilterSchema),z.string() ]).optional(),
  action: z.union([ z.lazy(() => StringFilterSchema),z.string() ]).optional(),
  userId: z.union([ z.lazy(() => StringNullableFilterSchema),z.string() ]).optional().nullable(),
  metadata: z.lazy(() => JsonNullableFilterSchema).optional(),
  createdAt: z.union([ z.lazy(() => DateTimeFilterSchema),z.coerce.date() ]).optional(),
  document: z.union([ z.lazy(() => DocumentScalarRelationFilterSchema),z.lazy(() => DocumentWhereInputSchema) ]).optional(),
}).strict();

export const AuditLogOrderByWithRelationInputSchema: z.ZodType<Prisma.AuditLogOrderByWithRelationInput> = z.object({
  id: z.lazy(() => SortOrderSchema).optional(),
  documentId: z.lazy(() => SortOrderSchema).optional(),
  action: z.lazy(() => SortOrderSchema).optional(),
  userId: z.union([ z.lazy(() => SortOrderSchema),z.lazy(() => SortOrderInputSchema) ]).optional(),
  metadata: z.union([ z.lazy(() => SortOrderSchema),z.lazy(() => SortOrderInputSchema) ]).optional(),
  createdAt: z.lazy(() => SortOrderSchema).optional(),
  document: z.lazy(() => DocumentOrderByWithRelationInputSchema).optional()
}).strict();

export const AuditLogWhereUniqueInputSchema: z.ZodType<Prisma.AuditLogWhereUniqueInput> = z.object({
  id: z.string().uuid()
})
.and(z.object({
  id: z.string().uuid().optional(),
  AND: z.union([ z.lazy(() => AuditLogWhereInputSchema),z.lazy(() => AuditLogWhereInputSchema).array() ]).optional(),
  OR: z.lazy(() => AuditLogWhereInputSchema).array().optional(),
  NOT: z.union([ z.lazy(() => AuditLogWhereInputSchema),z.lazy(() => AuditLogWhereInputSchema).array() ]).optional(),
  documentId: z.union([ z.lazy(() => StringFilterSchema),z.string() ]).optional(),
  action: z.union([ z.lazy(() => StringFilterSchema),z.string() ]).optional(),
  userId: z.union([ z.lazy(() => StringNullableFilterSchema),z.string() ]).optional().nullable(),
  metadata: z.lazy(() => JsonNullableFilterSchema).optional(),
  createdAt: z.union([ z.lazy(() => DateTimeFilterSchema),z.coerce.date() ]).optional(),
  document: z.union([ z.lazy(() => DocumentScalarRelationFilterSchema),z.lazy(() => DocumentWhereInputSchema) ]).optional(),
}).strict());

export const AuditLogOrderByWithAggregationInputSchema: z.ZodType<Prisma.AuditLogOrderByWithAggregationInput> = z.object({
  id: z.lazy(() => SortOrderSchema).optional(),
  documentId: z.lazy(() => SortOrderSchema).optional(),
  action: z.lazy(() => SortOrderSchema).optional(),
  userId: z.union([ z.lazy(() => SortOrderSchema),z.lazy(() => SortOrderInputSchema) ]).optional(),
  metadata: z.union([ z.lazy(() => SortOrderSchema),z.lazy(() => SortOrderInputSchema) ]).optional(),
  createdAt: z.lazy(() => SortOrderSchema).optional(),
  _count: z.lazy(() => AuditLogCountOrderByAggregateInputSchema).optional(),
  _max: z.lazy(() => AuditLogMaxOrderByAggregateInputSchema).optional(),
  _min: z.lazy(() => AuditLogMinOrderByAggregateInputSchema).optional()
}).strict();

export const AuditLogScalarWhereWithAggregatesInputSchema: z.ZodType<Prisma.AuditLogScalarWhereWithAggregatesInput> = z.object({
  AND: z.union([ z.lazy(() => AuditLogScalarWhereWithAggregatesInputSchema),z.lazy(() => AuditLogScalarWhereWithAggregatesInputSchema).array() ]).optional(),
  OR: z.lazy(() => AuditLogScalarWhereWithAggregatesInputSchema).array().optional(),
  NOT: z.union([ z.lazy(() => AuditLogScalarWhereWithAggregatesInputSchema),z.lazy(() => AuditLogScalarWhereWithAggregatesInputSchema).array() ]).optional(),
  id: z.union([ z.lazy(() => StringWithAggregatesFilterSchema),z.string() ]).optional(),
  documentId: z.union([ z.lazy(() => StringWithAggregatesFilterSchema),z.string() ]).optional(),
  action: z.union([ z.lazy(() => StringWithAggregatesFilterSchema),z.string() ]).optional(),
  userId: z.union([ z.lazy(() => StringNullableWithAggregatesFilterSchema),z.string() ]).optional().nullable(),
  metadata: z.lazy(() => JsonNullableWithAggregatesFilterSchema).optional(),
  createdAt: z.union([ z.lazy(() => DateTimeWithAggregatesFilterSchema),z.coerce.date() ]).optional(),
}).strict();

export const UserCreateInputSchema: z.ZodType<Prisma.UserCreateInput> = z.object({
  id: z.string().uuid().optional(),
  email: z.string(),
  name: z.string(),
  role: z.lazy(() => UserRoleSchema).optional(),
  createdAt: z.coerce.date().optional(),
  updatedAt: z.coerce.date().optional(),
  company: z.lazy(() => CompanyCreateNestedOneWithoutUsersInputSchema),
  documents: z.lazy(() => DocumentCreateNestedManyWithoutUserInputSchema).optional(),
  signatures: z.lazy(() => SignatureCreateNestedManyWithoutUserInputSchema).optional(),
  apiKeys: z.lazy(() => ApiKeyCreateNestedManyWithoutUserInputSchema).optional()
}).strict();

export const UserUncheckedCreateInputSchema: z.ZodType<Prisma.UserUncheckedCreateInput> = z.object({
  id: z.string().uuid().optional(),
  email: z.string(),
  name: z.string(),
  companyId: z.number().int(),
  role: z.lazy(() => UserRoleSchema).optional(),
  createdAt: z.coerce.date().optional(),
  updatedAt: z.coerce.date().optional(),
  documents: z.lazy(() => DocumentUncheckedCreateNestedManyWithoutUserInputSchema).optional(),
  signatures: z.lazy(() => SignatureUncheckedCreateNestedManyWithoutUserInputSchema).optional(),
  apiKeys: z.lazy(() => ApiKeyUncheckedCreateNestedManyWithoutUserInputSchema).optional()
}).strict();

export const UserUpdateInputSchema: z.ZodType<Prisma.UserUpdateInput> = z.object({
  id: z.union([ z.string().uuid(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  email: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  name: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  role: z.union([ z.lazy(() => UserRoleSchema),z.lazy(() => EnumUserRoleFieldUpdateOperationsInputSchema) ]).optional(),
  createdAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  updatedAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  company: z.lazy(() => CompanyUpdateOneRequiredWithoutUsersNestedInputSchema).optional(),
  documents: z.lazy(() => DocumentUpdateManyWithoutUserNestedInputSchema).optional(),
  signatures: z.lazy(() => SignatureUpdateManyWithoutUserNestedInputSchema).optional(),
  apiKeys: z.lazy(() => ApiKeyUpdateManyWithoutUserNestedInputSchema).optional()
}).strict();

export const UserUncheckedUpdateInputSchema: z.ZodType<Prisma.UserUncheckedUpdateInput> = z.object({
  id: z.union([ z.string().uuid(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  email: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  name: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  companyId: z.union([ z.number().int(),z.lazy(() => IntFieldUpdateOperationsInputSchema) ]).optional(),
  role: z.union([ z.lazy(() => UserRoleSchema),z.lazy(() => EnumUserRoleFieldUpdateOperationsInputSchema) ]).optional(),
  createdAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  updatedAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  documents: z.lazy(() => DocumentUncheckedUpdateManyWithoutUserNestedInputSchema).optional(),
  signatures: z.lazy(() => SignatureUncheckedUpdateManyWithoutUserNestedInputSchema).optional(),
  apiKeys: z.lazy(() => ApiKeyUncheckedUpdateManyWithoutUserNestedInputSchema).optional()
}).strict();

export const UserCreateManyInputSchema: z.ZodType<Prisma.UserCreateManyInput> = z.object({
  id: z.string().uuid().optional(),
  email: z.string(),
  name: z.string(),
  companyId: z.number().int(),
  role: z.lazy(() => UserRoleSchema).optional(),
  createdAt: z.coerce.date().optional(),
  updatedAt: z.coerce.date().optional()
}).strict();

export const UserUpdateManyMutationInputSchema: z.ZodType<Prisma.UserUpdateManyMutationInput> = z.object({
  id: z.union([ z.string().uuid(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  email: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  name: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  role: z.union([ z.lazy(() => UserRoleSchema),z.lazy(() => EnumUserRoleFieldUpdateOperationsInputSchema) ]).optional(),
  createdAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  updatedAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
}).strict();

export const UserUncheckedUpdateManyInputSchema: z.ZodType<Prisma.UserUncheckedUpdateManyInput> = z.object({
  id: z.union([ z.string().uuid(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  email: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  name: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  companyId: z.union([ z.number().int(),z.lazy(() => IntFieldUpdateOperationsInputSchema) ]).optional(),
  role: z.union([ z.lazy(() => UserRoleSchema),z.lazy(() => EnumUserRoleFieldUpdateOperationsInputSchema) ]).optional(),
  createdAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  updatedAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
}).strict();

export const CompanyCreateInputSchema: z.ZodType<Prisma.CompanyCreateInput> = z.object({
  id: z.number().int(),
  name: z.string(),
  adminEmail: z.string(),
  country: z.string(),
  rootCertificate: z.string().optional().nullable(),
  subscriptionId: z.string().optional().nullable(),
  createdAt: z.coerce.date().optional(),
  updatedAt: z.coerce.date().optional(),
  users: z.lazy(() => UserCreateNestedManyWithoutCompanyInputSchema).optional(),
  documents: z.lazy(() => DocumentCreateNestedManyWithoutCompanyInputSchema).optional(),
  certificates: z.lazy(() => CertificateCreateNestedManyWithoutCompanyInputSchema).optional(),
  blockchainWallet: z.lazy(() => BlockchainWalletCreateNestedOneWithoutCompanyInputSchema).optional(),
  SigningTemplate: z.lazy(() => SigningTemplateCreateNestedManyWithoutCompanyInputSchema).optional(),
  ApiKey: z.lazy(() => ApiKeyCreateNestedManyWithoutCompanyInputSchema).optional()
}).strict();

export const CompanyUncheckedCreateInputSchema: z.ZodType<Prisma.CompanyUncheckedCreateInput> = z.object({
  id: z.number().int(),
  name: z.string(),
  adminEmail: z.string(),
  country: z.string(),
  rootCertificate: z.string().optional().nullable(),
  subscriptionId: z.string().optional().nullable(),
  createdAt: z.coerce.date().optional(),
  updatedAt: z.coerce.date().optional(),
  users: z.lazy(() => UserUncheckedCreateNestedManyWithoutCompanyInputSchema).optional(),
  documents: z.lazy(() => DocumentUncheckedCreateNestedManyWithoutCompanyInputSchema).optional(),
  certificates: z.lazy(() => CertificateUncheckedCreateNestedManyWithoutCompanyInputSchema).optional(),
  blockchainWallet: z.lazy(() => BlockchainWalletUncheckedCreateNestedOneWithoutCompanyInputSchema).optional(),
  SigningTemplate: z.lazy(() => SigningTemplateUncheckedCreateNestedManyWithoutCompanyInputSchema).optional(),
  ApiKey: z.lazy(() => ApiKeyUncheckedCreateNestedManyWithoutCompanyInputSchema).optional()
}).strict();

export const CompanyUpdateInputSchema: z.ZodType<Prisma.CompanyUpdateInput> = z.object({
  id: z.union([ z.number().int(),z.lazy(() => IntFieldUpdateOperationsInputSchema) ]).optional(),
  name: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  adminEmail: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  country: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  rootCertificate: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  subscriptionId: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  createdAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  updatedAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  users: z.lazy(() => UserUpdateManyWithoutCompanyNestedInputSchema).optional(),
  documents: z.lazy(() => DocumentUpdateManyWithoutCompanyNestedInputSchema).optional(),
  certificates: z.lazy(() => CertificateUpdateManyWithoutCompanyNestedInputSchema).optional(),
  blockchainWallet: z.lazy(() => BlockchainWalletUpdateOneWithoutCompanyNestedInputSchema).optional(),
  SigningTemplate: z.lazy(() => SigningTemplateUpdateManyWithoutCompanyNestedInputSchema).optional(),
  ApiKey: z.lazy(() => ApiKeyUpdateManyWithoutCompanyNestedInputSchema).optional()
}).strict();

export const CompanyUncheckedUpdateInputSchema: z.ZodType<Prisma.CompanyUncheckedUpdateInput> = z.object({
  id: z.union([ z.number().int(),z.lazy(() => IntFieldUpdateOperationsInputSchema) ]).optional(),
  name: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  adminEmail: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  country: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  rootCertificate: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  subscriptionId: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  createdAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  updatedAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  users: z.lazy(() => UserUncheckedUpdateManyWithoutCompanyNestedInputSchema).optional(),
  documents: z.lazy(() => DocumentUncheckedUpdateManyWithoutCompanyNestedInputSchema).optional(),
  certificates: z.lazy(() => CertificateUncheckedUpdateManyWithoutCompanyNestedInputSchema).optional(),
  blockchainWallet: z.lazy(() => BlockchainWalletUncheckedUpdateOneWithoutCompanyNestedInputSchema).optional(),
  SigningTemplate: z.lazy(() => SigningTemplateUncheckedUpdateManyWithoutCompanyNestedInputSchema).optional(),
  ApiKey: z.lazy(() => ApiKeyUncheckedUpdateManyWithoutCompanyNestedInputSchema).optional()
}).strict();

export const CompanyCreateManyInputSchema: z.ZodType<Prisma.CompanyCreateManyInput> = z.object({
  id: z.number().int(),
  name: z.string(),
  adminEmail: z.string(),
  country: z.string(),
  rootCertificate: z.string().optional().nullable(),
  subscriptionId: z.string().optional().nullable(),
  createdAt: z.coerce.date().optional(),
  updatedAt: z.coerce.date().optional()
}).strict();

export const CompanyUpdateManyMutationInputSchema: z.ZodType<Prisma.CompanyUpdateManyMutationInput> = z.object({
  id: z.union([ z.number().int(),z.lazy(() => IntFieldUpdateOperationsInputSchema) ]).optional(),
  name: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  adminEmail: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  country: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  rootCertificate: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  subscriptionId: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  createdAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  updatedAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
}).strict();

export const CompanyUncheckedUpdateManyInputSchema: z.ZodType<Prisma.CompanyUncheckedUpdateManyInput> = z.object({
  id: z.union([ z.number().int(),z.lazy(() => IntFieldUpdateOperationsInputSchema) ]).optional(),
  name: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  adminEmail: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  country: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  rootCertificate: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  subscriptionId: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  createdAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  updatedAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
}).strict();

export const DocumentCreateInputSchema: z.ZodType<Prisma.DocumentCreateInput> = z.object({
  id: z.string().uuid().optional(),
  title: z.string().optional().nullable(),
  description: z.string().optional().nullable(),
  status: z.lazy(() => DocumentStatusSchema).optional(),
  fileUrl: z.string(),
  fileHash: z.string().optional().nullable(),
  blockchainDocId: z.string().optional().nullable(),
  metadata: z.union([ z.lazy(() => NullableJsonNullValueInputSchema),InputJsonValueSchema ]).optional(),
  expiresAt: z.coerce.date().optional().nullable(),
  createdAt: z.coerce.date().optional(),
  updatedAt: z.coerce.date().optional(),
  user: z.lazy(() => UserCreateNestedOneWithoutDocumentsInputSchema),
  company: z.lazy(() => CompanyCreateNestedOneWithoutDocumentsInputSchema),
  signingTemplate: z.lazy(() => SigningTemplateCreateNestedOneWithoutDocumentsInputSchema).optional(),
  signers: z.lazy(() => DocumentSignerCreateNestedManyWithoutDocumentInputSchema).optional(),
  signatures: z.lazy(() => SignatureCreateNestedManyWithoutDocumentInputSchema).optional(),
  auditLogs: z.lazy(() => AuditLogCreateNestedManyWithoutDocumentInputSchema).optional(),
  SignatureField: z.lazy(() => SignatureFieldCreateNestedManyWithoutDocumentInputSchema).optional()
}).strict();

export const DocumentUncheckedCreateInputSchema: z.ZodType<Prisma.DocumentUncheckedCreateInput> = z.object({
  id: z.string().uuid().optional(),
  title: z.string().optional().nullable(),
  description: z.string().optional().nullable(),
  userId: z.string(),
  companyId: z.number().int(),
  status: z.lazy(() => DocumentStatusSchema).optional(),
  fileUrl: z.string(),
  fileHash: z.string().optional().nullable(),
  blockchainDocId: z.string().optional().nullable(),
  templateId: z.string().optional().nullable(),
  metadata: z.union([ z.lazy(() => NullableJsonNullValueInputSchema),InputJsonValueSchema ]).optional(),
  expiresAt: z.coerce.date().optional().nullable(),
  createdAt: z.coerce.date().optional(),
  updatedAt: z.coerce.date().optional(),
  signers: z.lazy(() => DocumentSignerUncheckedCreateNestedManyWithoutDocumentInputSchema).optional(),
  signatures: z.lazy(() => SignatureUncheckedCreateNestedManyWithoutDocumentInputSchema).optional(),
  auditLogs: z.lazy(() => AuditLogUncheckedCreateNestedManyWithoutDocumentInputSchema).optional(),
  SignatureField: z.lazy(() => SignatureFieldUncheckedCreateNestedManyWithoutDocumentInputSchema).optional()
}).strict();

export const DocumentUpdateInputSchema: z.ZodType<Prisma.DocumentUpdateInput> = z.object({
  id: z.union([ z.string().uuid(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  title: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  description: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  status: z.union([ z.lazy(() => DocumentStatusSchema),z.lazy(() => EnumDocumentStatusFieldUpdateOperationsInputSchema) ]).optional(),
  fileUrl: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  fileHash: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  blockchainDocId: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  metadata: z.union([ z.lazy(() => NullableJsonNullValueInputSchema),InputJsonValueSchema ]).optional(),
  expiresAt: z.union([ z.coerce.date(),z.lazy(() => NullableDateTimeFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  createdAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  updatedAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  user: z.lazy(() => UserUpdateOneRequiredWithoutDocumentsNestedInputSchema).optional(),
  company: z.lazy(() => CompanyUpdateOneRequiredWithoutDocumentsNestedInputSchema).optional(),
  signingTemplate: z.lazy(() => SigningTemplateUpdateOneWithoutDocumentsNestedInputSchema).optional(),
  signers: z.lazy(() => DocumentSignerUpdateManyWithoutDocumentNestedInputSchema).optional(),
  signatures: z.lazy(() => SignatureUpdateManyWithoutDocumentNestedInputSchema).optional(),
  auditLogs: z.lazy(() => AuditLogUpdateManyWithoutDocumentNestedInputSchema).optional(),
  SignatureField: z.lazy(() => SignatureFieldUpdateManyWithoutDocumentNestedInputSchema).optional()
}).strict();

export const DocumentUncheckedUpdateInputSchema: z.ZodType<Prisma.DocumentUncheckedUpdateInput> = z.object({
  id: z.union([ z.string().uuid(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  title: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  description: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  userId: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  companyId: z.union([ z.number().int(),z.lazy(() => IntFieldUpdateOperationsInputSchema) ]).optional(),
  status: z.union([ z.lazy(() => DocumentStatusSchema),z.lazy(() => EnumDocumentStatusFieldUpdateOperationsInputSchema) ]).optional(),
  fileUrl: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  fileHash: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  blockchainDocId: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  templateId: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  metadata: z.union([ z.lazy(() => NullableJsonNullValueInputSchema),InputJsonValueSchema ]).optional(),
  expiresAt: z.union([ z.coerce.date(),z.lazy(() => NullableDateTimeFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  createdAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  updatedAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  signers: z.lazy(() => DocumentSignerUncheckedUpdateManyWithoutDocumentNestedInputSchema).optional(),
  signatures: z.lazy(() => SignatureUncheckedUpdateManyWithoutDocumentNestedInputSchema).optional(),
  auditLogs: z.lazy(() => AuditLogUncheckedUpdateManyWithoutDocumentNestedInputSchema).optional(),
  SignatureField: z.lazy(() => SignatureFieldUncheckedUpdateManyWithoutDocumentNestedInputSchema).optional()
}).strict();

export const DocumentCreateManyInputSchema: z.ZodType<Prisma.DocumentCreateManyInput> = z.object({
  id: z.string().uuid().optional(),
  title: z.string().optional().nullable(),
  description: z.string().optional().nullable(),
  userId: z.string(),
  companyId: z.number().int(),
  status: z.lazy(() => DocumentStatusSchema).optional(),
  fileUrl: z.string(),
  fileHash: z.string().optional().nullable(),
  blockchainDocId: z.string().optional().nullable(),
  templateId: z.string().optional().nullable(),
  metadata: z.union([ z.lazy(() => NullableJsonNullValueInputSchema),InputJsonValueSchema ]).optional(),
  expiresAt: z.coerce.date().optional().nullable(),
  createdAt: z.coerce.date().optional(),
  updatedAt: z.coerce.date().optional()
}).strict();

export const DocumentUpdateManyMutationInputSchema: z.ZodType<Prisma.DocumentUpdateManyMutationInput> = z.object({
  id: z.union([ z.string().uuid(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  title: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  description: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  status: z.union([ z.lazy(() => DocumentStatusSchema),z.lazy(() => EnumDocumentStatusFieldUpdateOperationsInputSchema) ]).optional(),
  fileUrl: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  fileHash: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  blockchainDocId: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  metadata: z.union([ z.lazy(() => NullableJsonNullValueInputSchema),InputJsonValueSchema ]).optional(),
  expiresAt: z.union([ z.coerce.date(),z.lazy(() => NullableDateTimeFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  createdAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  updatedAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
}).strict();

export const DocumentUncheckedUpdateManyInputSchema: z.ZodType<Prisma.DocumentUncheckedUpdateManyInput> = z.object({
  id: z.union([ z.string().uuid(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  title: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  description: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  userId: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  companyId: z.union([ z.number().int(),z.lazy(() => IntFieldUpdateOperationsInputSchema) ]).optional(),
  status: z.union([ z.lazy(() => DocumentStatusSchema),z.lazy(() => EnumDocumentStatusFieldUpdateOperationsInputSchema) ]).optional(),
  fileUrl: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  fileHash: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  blockchainDocId: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  templateId: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  metadata: z.union([ z.lazy(() => NullableJsonNullValueInputSchema),InputJsonValueSchema ]).optional(),
  expiresAt: z.union([ z.coerce.date(),z.lazy(() => NullableDateTimeFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  createdAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  updatedAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
}).strict();

export const DocumentSignerCreateInputSchema: z.ZodType<Prisma.DocumentSignerCreateInput> = z.object({
  id: z.string().uuid().optional(),
  email: z.string(),
  name: z.string().optional().nullable(),
  order: z.number().int(),
  status: z.lazy(() => SignerStatusSchema).optional(),
  expiresAt: z.coerce.date().optional().nullable(),
  notifiedAt: z.coerce.date().optional().nullable(),
  createdAt: z.coerce.date().optional(),
  updatedAt: z.coerce.date().optional(),
  document: z.lazy(() => DocumentCreateNestedOneWithoutSignersInputSchema),
  signatureFields: z.lazy(() => SignatureFieldCreateNestedManyWithoutSignerInputSchema).optional(),
  signature: z.lazy(() => SignatureCreateNestedOneWithoutDocumentSignerInputSchema).optional()
}).strict();

export const DocumentSignerUncheckedCreateInputSchema: z.ZodType<Prisma.DocumentSignerUncheckedCreateInput> = z.object({
  id: z.string().uuid().optional(),
  documentId: z.string(),
  email: z.string(),
  name: z.string().optional().nullable(),
  order: z.number().int(),
  status: z.lazy(() => SignerStatusSchema).optional(),
  expiresAt: z.coerce.date().optional().nullable(),
  notifiedAt: z.coerce.date().optional().nullable(),
  createdAt: z.coerce.date().optional(),
  updatedAt: z.coerce.date().optional(),
  signatureId: z.string().optional().nullable(),
  signatureFields: z.lazy(() => SignatureFieldUncheckedCreateNestedManyWithoutSignerInputSchema).optional()
}).strict();

export const DocumentSignerUpdateInputSchema: z.ZodType<Prisma.DocumentSignerUpdateInput> = z.object({
  id: z.union([ z.string().uuid(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  email: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  name: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  order: z.union([ z.number().int(),z.lazy(() => IntFieldUpdateOperationsInputSchema) ]).optional(),
  status: z.union([ z.lazy(() => SignerStatusSchema),z.lazy(() => EnumSignerStatusFieldUpdateOperationsInputSchema) ]).optional(),
  expiresAt: z.union([ z.coerce.date(),z.lazy(() => NullableDateTimeFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  notifiedAt: z.union([ z.coerce.date(),z.lazy(() => NullableDateTimeFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  createdAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  updatedAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  document: z.lazy(() => DocumentUpdateOneRequiredWithoutSignersNestedInputSchema).optional(),
  signatureFields: z.lazy(() => SignatureFieldUpdateManyWithoutSignerNestedInputSchema).optional(),
  signature: z.lazy(() => SignatureUpdateOneWithoutDocumentSignerNestedInputSchema).optional()
}).strict();

export const DocumentSignerUncheckedUpdateInputSchema: z.ZodType<Prisma.DocumentSignerUncheckedUpdateInput> = z.object({
  id: z.union([ z.string().uuid(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  documentId: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  email: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  name: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  order: z.union([ z.number().int(),z.lazy(() => IntFieldUpdateOperationsInputSchema) ]).optional(),
  status: z.union([ z.lazy(() => SignerStatusSchema),z.lazy(() => EnumSignerStatusFieldUpdateOperationsInputSchema) ]).optional(),
  expiresAt: z.union([ z.coerce.date(),z.lazy(() => NullableDateTimeFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  notifiedAt: z.union([ z.coerce.date(),z.lazy(() => NullableDateTimeFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  createdAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  updatedAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  signatureId: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  signatureFields: z.lazy(() => SignatureFieldUncheckedUpdateManyWithoutSignerNestedInputSchema).optional()
}).strict();

export const DocumentSignerCreateManyInputSchema: z.ZodType<Prisma.DocumentSignerCreateManyInput> = z.object({
  id: z.string().uuid().optional(),
  documentId: z.string(),
  email: z.string(),
  name: z.string().optional().nullable(),
  order: z.number().int(),
  status: z.lazy(() => SignerStatusSchema).optional(),
  expiresAt: z.coerce.date().optional().nullable(),
  notifiedAt: z.coerce.date().optional().nullable(),
  createdAt: z.coerce.date().optional(),
  updatedAt: z.coerce.date().optional(),
  signatureId: z.string().optional().nullable()
}).strict();

export const DocumentSignerUpdateManyMutationInputSchema: z.ZodType<Prisma.DocumentSignerUpdateManyMutationInput> = z.object({
  id: z.union([ z.string().uuid(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  email: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  name: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  order: z.union([ z.number().int(),z.lazy(() => IntFieldUpdateOperationsInputSchema) ]).optional(),
  status: z.union([ z.lazy(() => SignerStatusSchema),z.lazy(() => EnumSignerStatusFieldUpdateOperationsInputSchema) ]).optional(),
  expiresAt: z.union([ z.coerce.date(),z.lazy(() => NullableDateTimeFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  notifiedAt: z.union([ z.coerce.date(),z.lazy(() => NullableDateTimeFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  createdAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  updatedAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
}).strict();

export const DocumentSignerUncheckedUpdateManyInputSchema: z.ZodType<Prisma.DocumentSignerUncheckedUpdateManyInput> = z.object({
  id: z.union([ z.string().uuid(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  documentId: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  email: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  name: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  order: z.union([ z.number().int(),z.lazy(() => IntFieldUpdateOperationsInputSchema) ]).optional(),
  status: z.union([ z.lazy(() => SignerStatusSchema),z.lazy(() => EnumSignerStatusFieldUpdateOperationsInputSchema) ]).optional(),
  expiresAt: z.union([ z.coerce.date(),z.lazy(() => NullableDateTimeFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  notifiedAt: z.union([ z.coerce.date(),z.lazy(() => NullableDateTimeFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  createdAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  updatedAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  signatureId: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
}).strict();

export const SignatureFieldCreateInputSchema: z.ZodType<Prisma.SignatureFieldCreateInput> = z.object({
  id: z.string().uuid().optional(),
  type: z.lazy(() => FieldTypeSchema).optional(),
  required: z.boolean().optional(),
  page: z.number().int(),
  x: z.number(),
  y: z.number(),
  width: z.number(),
  height: z.number(),
  signedAt: z.coerce.date().optional().nullable(),
  createdAt: z.coerce.date().optional(),
  updatedAt: z.coerce.date().optional(),
  document: z.lazy(() => DocumentCreateNestedOneWithoutSignatureFieldInputSchema),
  signer: z.lazy(() => DocumentSignerCreateNestedOneWithoutSignatureFieldsInputSchema)
}).strict();

export const SignatureFieldUncheckedCreateInputSchema: z.ZodType<Prisma.SignatureFieldUncheckedCreateInput> = z.object({
  id: z.string().uuid().optional(),
  documentId: z.string(),
  signerId: z.string(),
  type: z.lazy(() => FieldTypeSchema).optional(),
  required: z.boolean().optional(),
  page: z.number().int(),
  x: z.number(),
  y: z.number(),
  width: z.number(),
  height: z.number(),
  signedAt: z.coerce.date().optional().nullable(),
  createdAt: z.coerce.date().optional(),
  updatedAt: z.coerce.date().optional()
}).strict();

export const SignatureFieldUpdateInputSchema: z.ZodType<Prisma.SignatureFieldUpdateInput> = z.object({
  id: z.union([ z.string().uuid(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  type: z.union([ z.lazy(() => FieldTypeSchema),z.lazy(() => EnumFieldTypeFieldUpdateOperationsInputSchema) ]).optional(),
  required: z.union([ z.boolean(),z.lazy(() => BoolFieldUpdateOperationsInputSchema) ]).optional(),
  page: z.union([ z.number().int(),z.lazy(() => IntFieldUpdateOperationsInputSchema) ]).optional(),
  x: z.union([ z.number(),z.lazy(() => FloatFieldUpdateOperationsInputSchema) ]).optional(),
  y: z.union([ z.number(),z.lazy(() => FloatFieldUpdateOperationsInputSchema) ]).optional(),
  width: z.union([ z.number(),z.lazy(() => FloatFieldUpdateOperationsInputSchema) ]).optional(),
  height: z.union([ z.number(),z.lazy(() => FloatFieldUpdateOperationsInputSchema) ]).optional(),
  signedAt: z.union([ z.coerce.date(),z.lazy(() => NullableDateTimeFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  createdAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  updatedAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  document: z.lazy(() => DocumentUpdateOneRequiredWithoutSignatureFieldNestedInputSchema).optional(),
  signer: z.lazy(() => DocumentSignerUpdateOneRequiredWithoutSignatureFieldsNestedInputSchema).optional()
}).strict();

export const SignatureFieldUncheckedUpdateInputSchema: z.ZodType<Prisma.SignatureFieldUncheckedUpdateInput> = z.object({
  id: z.union([ z.string().uuid(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  documentId: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  signerId: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  type: z.union([ z.lazy(() => FieldTypeSchema),z.lazy(() => EnumFieldTypeFieldUpdateOperationsInputSchema) ]).optional(),
  required: z.union([ z.boolean(),z.lazy(() => BoolFieldUpdateOperationsInputSchema) ]).optional(),
  page: z.union([ z.number().int(),z.lazy(() => IntFieldUpdateOperationsInputSchema) ]).optional(),
  x: z.union([ z.number(),z.lazy(() => FloatFieldUpdateOperationsInputSchema) ]).optional(),
  y: z.union([ z.number(),z.lazy(() => FloatFieldUpdateOperationsInputSchema) ]).optional(),
  width: z.union([ z.number(),z.lazy(() => FloatFieldUpdateOperationsInputSchema) ]).optional(),
  height: z.union([ z.number(),z.lazy(() => FloatFieldUpdateOperationsInputSchema) ]).optional(),
  signedAt: z.union([ z.coerce.date(),z.lazy(() => NullableDateTimeFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  createdAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  updatedAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
}).strict();

export const SignatureFieldCreateManyInputSchema: z.ZodType<Prisma.SignatureFieldCreateManyInput> = z.object({
  id: z.string().uuid().optional(),
  documentId: z.string(),
  signerId: z.string(),
  type: z.lazy(() => FieldTypeSchema).optional(),
  required: z.boolean().optional(),
  page: z.number().int(),
  x: z.number(),
  y: z.number(),
  width: z.number(),
  height: z.number(),
  signedAt: z.coerce.date().optional().nullable(),
  createdAt: z.coerce.date().optional(),
  updatedAt: z.coerce.date().optional()
}).strict();

export const SignatureFieldUpdateManyMutationInputSchema: z.ZodType<Prisma.SignatureFieldUpdateManyMutationInput> = z.object({
  id: z.union([ z.string().uuid(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  type: z.union([ z.lazy(() => FieldTypeSchema),z.lazy(() => EnumFieldTypeFieldUpdateOperationsInputSchema) ]).optional(),
  required: z.union([ z.boolean(),z.lazy(() => BoolFieldUpdateOperationsInputSchema) ]).optional(),
  page: z.union([ z.number().int(),z.lazy(() => IntFieldUpdateOperationsInputSchema) ]).optional(),
  x: z.union([ z.number(),z.lazy(() => FloatFieldUpdateOperationsInputSchema) ]).optional(),
  y: z.union([ z.number(),z.lazy(() => FloatFieldUpdateOperationsInputSchema) ]).optional(),
  width: z.union([ z.number(),z.lazy(() => FloatFieldUpdateOperationsInputSchema) ]).optional(),
  height: z.union([ z.number(),z.lazy(() => FloatFieldUpdateOperationsInputSchema) ]).optional(),
  signedAt: z.union([ z.coerce.date(),z.lazy(() => NullableDateTimeFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  createdAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  updatedAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
}).strict();

export const SignatureFieldUncheckedUpdateManyInputSchema: z.ZodType<Prisma.SignatureFieldUncheckedUpdateManyInput> = z.object({
  id: z.union([ z.string().uuid(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  documentId: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  signerId: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  type: z.union([ z.lazy(() => FieldTypeSchema),z.lazy(() => EnumFieldTypeFieldUpdateOperationsInputSchema) ]).optional(),
  required: z.union([ z.boolean(),z.lazy(() => BoolFieldUpdateOperationsInputSchema) ]).optional(),
  page: z.union([ z.number().int(),z.lazy(() => IntFieldUpdateOperationsInputSchema) ]).optional(),
  x: z.union([ z.number(),z.lazy(() => FloatFieldUpdateOperationsInputSchema) ]).optional(),
  y: z.union([ z.number(),z.lazy(() => FloatFieldUpdateOperationsInputSchema) ]).optional(),
  width: z.union([ z.number(),z.lazy(() => FloatFieldUpdateOperationsInputSchema) ]).optional(),
  height: z.union([ z.number(),z.lazy(() => FloatFieldUpdateOperationsInputSchema) ]).optional(),
  signedAt: z.union([ z.coerce.date(),z.lazy(() => NullableDateTimeFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  createdAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  updatedAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
}).strict();

export const SignatureCreateInputSchema: z.ZodType<Prisma.SignatureCreateInput> = z.object({
  id: z.string().uuid().optional(),
  signatureData: z.string(),
  visualSignature: z.string().optional().nullable(),
  blockchainTx: z.string().optional().nullable(),
  coordinates: z.union([ z.lazy(() => NullableJsonNullValueInputSchema),InputJsonValueSchema ]).optional(),
  metadata: z.union([ z.lazy(() => NullableJsonNullValueInputSchema),InputJsonValueSchema ]).optional(),
  createdAt: z.coerce.date().optional(),
  updatedAt: z.coerce.date().optional(),
  document: z.lazy(() => DocumentCreateNestedOneWithoutSignaturesInputSchema),
  user: z.lazy(() => UserCreateNestedOneWithoutSignaturesInputSchema),
  certificate: z.lazy(() => CertificateCreateNestedOneWithoutSignaturesInputSchema),
  DocumentSigner: z.lazy(() => DocumentSignerCreateNestedManyWithoutSignatureInputSchema).optional()
}).strict();

export const SignatureUncheckedCreateInputSchema: z.ZodType<Prisma.SignatureUncheckedCreateInput> = z.object({
  id: z.string().uuid().optional(),
  documentId: z.string(),
  userId: z.string(),
  certificateId: z.string(),
  signatureData: z.string(),
  visualSignature: z.string().optional().nullable(),
  blockchainTx: z.string().optional().nullable(),
  coordinates: z.union([ z.lazy(() => NullableJsonNullValueInputSchema),InputJsonValueSchema ]).optional(),
  metadata: z.union([ z.lazy(() => NullableJsonNullValueInputSchema),InputJsonValueSchema ]).optional(),
  createdAt: z.coerce.date().optional(),
  updatedAt: z.coerce.date().optional(),
  DocumentSigner: z.lazy(() => DocumentSignerUncheckedCreateNestedManyWithoutSignatureInputSchema).optional()
}).strict();

export const SignatureUpdateInputSchema: z.ZodType<Prisma.SignatureUpdateInput> = z.object({
  id: z.union([ z.string().uuid(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  signatureData: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  visualSignature: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  blockchainTx: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  coordinates: z.union([ z.lazy(() => NullableJsonNullValueInputSchema),InputJsonValueSchema ]).optional(),
  metadata: z.union([ z.lazy(() => NullableJsonNullValueInputSchema),InputJsonValueSchema ]).optional(),
  createdAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  updatedAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  document: z.lazy(() => DocumentUpdateOneRequiredWithoutSignaturesNestedInputSchema).optional(),
  user: z.lazy(() => UserUpdateOneRequiredWithoutSignaturesNestedInputSchema).optional(),
  certificate: z.lazy(() => CertificateUpdateOneRequiredWithoutSignaturesNestedInputSchema).optional(),
  DocumentSigner: z.lazy(() => DocumentSignerUpdateManyWithoutSignatureNestedInputSchema).optional()
}).strict();

export const SignatureUncheckedUpdateInputSchema: z.ZodType<Prisma.SignatureUncheckedUpdateInput> = z.object({
  id: z.union([ z.string().uuid(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  documentId: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  userId: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  certificateId: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  signatureData: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  visualSignature: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  blockchainTx: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  coordinates: z.union([ z.lazy(() => NullableJsonNullValueInputSchema),InputJsonValueSchema ]).optional(),
  metadata: z.union([ z.lazy(() => NullableJsonNullValueInputSchema),InputJsonValueSchema ]).optional(),
  createdAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  updatedAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  DocumentSigner: z.lazy(() => DocumentSignerUncheckedUpdateManyWithoutSignatureNestedInputSchema).optional()
}).strict();

export const SignatureCreateManyInputSchema: z.ZodType<Prisma.SignatureCreateManyInput> = z.object({
  id: z.string().uuid().optional(),
  documentId: z.string(),
  userId: z.string(),
  certificateId: z.string(),
  signatureData: z.string(),
  visualSignature: z.string().optional().nullable(),
  blockchainTx: z.string().optional().nullable(),
  coordinates: z.union([ z.lazy(() => NullableJsonNullValueInputSchema),InputJsonValueSchema ]).optional(),
  metadata: z.union([ z.lazy(() => NullableJsonNullValueInputSchema),InputJsonValueSchema ]).optional(),
  createdAt: z.coerce.date().optional(),
  updatedAt: z.coerce.date().optional()
}).strict();

export const SignatureUpdateManyMutationInputSchema: z.ZodType<Prisma.SignatureUpdateManyMutationInput> = z.object({
  id: z.union([ z.string().uuid(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  signatureData: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  visualSignature: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  blockchainTx: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  coordinates: z.union([ z.lazy(() => NullableJsonNullValueInputSchema),InputJsonValueSchema ]).optional(),
  metadata: z.union([ z.lazy(() => NullableJsonNullValueInputSchema),InputJsonValueSchema ]).optional(),
  createdAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  updatedAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
}).strict();

export const SignatureUncheckedUpdateManyInputSchema: z.ZodType<Prisma.SignatureUncheckedUpdateManyInput> = z.object({
  id: z.union([ z.string().uuid(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  documentId: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  userId: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  certificateId: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  signatureData: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  visualSignature: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  blockchainTx: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  coordinates: z.union([ z.lazy(() => NullableJsonNullValueInputSchema),InputJsonValueSchema ]).optional(),
  metadata: z.union([ z.lazy(() => NullableJsonNullValueInputSchema),InputJsonValueSchema ]).optional(),
  createdAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  updatedAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
}).strict();

export const CertificateCreateInputSchema: z.ZodType<Prisma.CertificateCreateInput> = z.object({
  id: z.string().uuid().optional(),
  fingerprint: z.string(),
  publicKey: z.string(),
  privateKey: z.string().optional().nullable(),
  isCA: z.boolean().optional(),
  issuerCertId: z.string().optional().nullable(),
  validFrom: z.coerce.date(),
  validTo: z.coerce.date(),
  metadata: z.union([ z.lazy(() => NullableJsonNullValueInputSchema),InputJsonValueSchema ]).optional(),
  createdAt: z.coerce.date().optional(),
  updatedAt: z.coerce.date().optional(),
  company: z.lazy(() => CompanyCreateNestedOneWithoutCertificatesInputSchema),
  signatures: z.lazy(() => SignatureCreateNestedManyWithoutCertificateInputSchema).optional()
}).strict();

export const CertificateUncheckedCreateInputSchema: z.ZodType<Prisma.CertificateUncheckedCreateInput> = z.object({
  id: z.string().uuid().optional(),
  companyId: z.number().int(),
  fingerprint: z.string(),
  publicKey: z.string(),
  privateKey: z.string().optional().nullable(),
  isCA: z.boolean().optional(),
  issuerCertId: z.string().optional().nullable(),
  validFrom: z.coerce.date(),
  validTo: z.coerce.date(),
  metadata: z.union([ z.lazy(() => NullableJsonNullValueInputSchema),InputJsonValueSchema ]).optional(),
  createdAt: z.coerce.date().optional(),
  updatedAt: z.coerce.date().optional(),
  signatures: z.lazy(() => SignatureUncheckedCreateNestedManyWithoutCertificateInputSchema).optional()
}).strict();

export const CertificateUpdateInputSchema: z.ZodType<Prisma.CertificateUpdateInput> = z.object({
  id: z.union([ z.string().uuid(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  fingerprint: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  publicKey: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  privateKey: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  isCA: z.union([ z.boolean(),z.lazy(() => BoolFieldUpdateOperationsInputSchema) ]).optional(),
  issuerCertId: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  validFrom: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  validTo: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  metadata: z.union([ z.lazy(() => NullableJsonNullValueInputSchema),InputJsonValueSchema ]).optional(),
  createdAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  updatedAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  company: z.lazy(() => CompanyUpdateOneRequiredWithoutCertificatesNestedInputSchema).optional(),
  signatures: z.lazy(() => SignatureUpdateManyWithoutCertificateNestedInputSchema).optional()
}).strict();

export const CertificateUncheckedUpdateInputSchema: z.ZodType<Prisma.CertificateUncheckedUpdateInput> = z.object({
  id: z.union([ z.string().uuid(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  companyId: z.union([ z.number().int(),z.lazy(() => IntFieldUpdateOperationsInputSchema) ]).optional(),
  fingerprint: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  publicKey: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  privateKey: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  isCA: z.union([ z.boolean(),z.lazy(() => BoolFieldUpdateOperationsInputSchema) ]).optional(),
  issuerCertId: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  validFrom: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  validTo: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  metadata: z.union([ z.lazy(() => NullableJsonNullValueInputSchema),InputJsonValueSchema ]).optional(),
  createdAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  updatedAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  signatures: z.lazy(() => SignatureUncheckedUpdateManyWithoutCertificateNestedInputSchema).optional()
}).strict();

export const CertificateCreateManyInputSchema: z.ZodType<Prisma.CertificateCreateManyInput> = z.object({
  id: z.string().uuid().optional(),
  companyId: z.number().int(),
  fingerprint: z.string(),
  publicKey: z.string(),
  privateKey: z.string().optional().nullable(),
  isCA: z.boolean().optional(),
  issuerCertId: z.string().optional().nullable(),
  validFrom: z.coerce.date(),
  validTo: z.coerce.date(),
  metadata: z.union([ z.lazy(() => NullableJsonNullValueInputSchema),InputJsonValueSchema ]).optional(),
  createdAt: z.coerce.date().optional(),
  updatedAt: z.coerce.date().optional()
}).strict();

export const CertificateUpdateManyMutationInputSchema: z.ZodType<Prisma.CertificateUpdateManyMutationInput> = z.object({
  id: z.union([ z.string().uuid(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  fingerprint: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  publicKey: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  privateKey: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  isCA: z.union([ z.boolean(),z.lazy(() => BoolFieldUpdateOperationsInputSchema) ]).optional(),
  issuerCertId: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  validFrom: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  validTo: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  metadata: z.union([ z.lazy(() => NullableJsonNullValueInputSchema),InputJsonValueSchema ]).optional(),
  createdAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  updatedAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
}).strict();

export const CertificateUncheckedUpdateManyInputSchema: z.ZodType<Prisma.CertificateUncheckedUpdateManyInput> = z.object({
  id: z.union([ z.string().uuid(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  companyId: z.union([ z.number().int(),z.lazy(() => IntFieldUpdateOperationsInputSchema) ]).optional(),
  fingerprint: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  publicKey: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  privateKey: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  isCA: z.union([ z.boolean(),z.lazy(() => BoolFieldUpdateOperationsInputSchema) ]).optional(),
  issuerCertId: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  validFrom: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  validTo: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  metadata: z.union([ z.lazy(() => NullableJsonNullValueInputSchema),InputJsonValueSchema ]).optional(),
  createdAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  updatedAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
}).strict();

export const SigningTemplateCreateInputSchema: z.ZodType<Prisma.SigningTemplateCreateInput> = z.object({
  id: z.string().uuid().optional(),
  name: z.string(),
  fields: z.union([ z.lazy(() => JsonNullValueInputSchema),InputJsonValueSchema ]),
  createdAt: z.coerce.date().optional(),
  updatedAt: z.coerce.date().optional(),
  company: z.lazy(() => CompanyCreateNestedOneWithoutSigningTemplateInputSchema),
  documents: z.lazy(() => DocumentCreateNestedManyWithoutSigningTemplateInputSchema).optional()
}).strict();

export const SigningTemplateUncheckedCreateInputSchema: z.ZodType<Prisma.SigningTemplateUncheckedCreateInput> = z.object({
  id: z.string().uuid().optional(),
  name: z.string(),
  companyId: z.number().int(),
  fields: z.union([ z.lazy(() => JsonNullValueInputSchema),InputJsonValueSchema ]),
  createdAt: z.coerce.date().optional(),
  updatedAt: z.coerce.date().optional(),
  documents: z.lazy(() => DocumentUncheckedCreateNestedManyWithoutSigningTemplateInputSchema).optional()
}).strict();

export const SigningTemplateUpdateInputSchema: z.ZodType<Prisma.SigningTemplateUpdateInput> = z.object({
  id: z.union([ z.string().uuid(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  name: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  fields: z.union([ z.lazy(() => JsonNullValueInputSchema),InputJsonValueSchema ]).optional(),
  createdAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  updatedAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  company: z.lazy(() => CompanyUpdateOneRequiredWithoutSigningTemplateNestedInputSchema).optional(),
  documents: z.lazy(() => DocumentUpdateManyWithoutSigningTemplateNestedInputSchema).optional()
}).strict();

export const SigningTemplateUncheckedUpdateInputSchema: z.ZodType<Prisma.SigningTemplateUncheckedUpdateInput> = z.object({
  id: z.union([ z.string().uuid(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  name: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  companyId: z.union([ z.number().int(),z.lazy(() => IntFieldUpdateOperationsInputSchema) ]).optional(),
  fields: z.union([ z.lazy(() => JsonNullValueInputSchema),InputJsonValueSchema ]).optional(),
  createdAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  updatedAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  documents: z.lazy(() => DocumentUncheckedUpdateManyWithoutSigningTemplateNestedInputSchema).optional()
}).strict();

export const SigningTemplateCreateManyInputSchema: z.ZodType<Prisma.SigningTemplateCreateManyInput> = z.object({
  id: z.string().uuid().optional(),
  name: z.string(),
  companyId: z.number().int(),
  fields: z.union([ z.lazy(() => JsonNullValueInputSchema),InputJsonValueSchema ]),
  createdAt: z.coerce.date().optional(),
  updatedAt: z.coerce.date().optional()
}).strict();

export const SigningTemplateUpdateManyMutationInputSchema: z.ZodType<Prisma.SigningTemplateUpdateManyMutationInput> = z.object({
  id: z.union([ z.string().uuid(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  name: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  fields: z.union([ z.lazy(() => JsonNullValueInputSchema),InputJsonValueSchema ]).optional(),
  createdAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  updatedAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
}).strict();

export const SigningTemplateUncheckedUpdateManyInputSchema: z.ZodType<Prisma.SigningTemplateUncheckedUpdateManyInput> = z.object({
  id: z.union([ z.string().uuid(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  name: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  companyId: z.union([ z.number().int(),z.lazy(() => IntFieldUpdateOperationsInputSchema) ]).optional(),
  fields: z.union([ z.lazy(() => JsonNullValueInputSchema),InputJsonValueSchema ]).optional(),
  createdAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  updatedAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
}).strict();

export const BlockchainWalletCreateInputSchema: z.ZodType<Prisma.BlockchainWalletCreateInput> = z.object({
  id: z.string().uuid().optional(),
  address: z.string(),
  privateKey: z.string().optional().nullable(),
  createdAt: z.coerce.date().optional(),
  updatedAt: z.coerce.date().optional(),
  company: z.lazy(() => CompanyCreateNestedOneWithoutBlockchainWalletInputSchema)
}).strict();

export const BlockchainWalletUncheckedCreateInputSchema: z.ZodType<Prisma.BlockchainWalletUncheckedCreateInput> = z.object({
  id: z.string().uuid().optional(),
  companyId: z.number().int(),
  address: z.string(),
  privateKey: z.string().optional().nullable(),
  createdAt: z.coerce.date().optional(),
  updatedAt: z.coerce.date().optional()
}).strict();

export const BlockchainWalletUpdateInputSchema: z.ZodType<Prisma.BlockchainWalletUpdateInput> = z.object({
  id: z.union([ z.string().uuid(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  address: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  privateKey: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  createdAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  updatedAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  company: z.lazy(() => CompanyUpdateOneRequiredWithoutBlockchainWalletNestedInputSchema).optional()
}).strict();

export const BlockchainWalletUncheckedUpdateInputSchema: z.ZodType<Prisma.BlockchainWalletUncheckedUpdateInput> = z.object({
  id: z.union([ z.string().uuid(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  companyId: z.union([ z.number().int(),z.lazy(() => IntFieldUpdateOperationsInputSchema) ]).optional(),
  address: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  privateKey: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  createdAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  updatedAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
}).strict();

export const BlockchainWalletCreateManyInputSchema: z.ZodType<Prisma.BlockchainWalletCreateManyInput> = z.object({
  id: z.string().uuid().optional(),
  companyId: z.number().int(),
  address: z.string(),
  privateKey: z.string().optional().nullable(),
  createdAt: z.coerce.date().optional(),
  updatedAt: z.coerce.date().optional()
}).strict();

export const BlockchainWalletUpdateManyMutationInputSchema: z.ZodType<Prisma.BlockchainWalletUpdateManyMutationInput> = z.object({
  id: z.union([ z.string().uuid(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  address: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  privateKey: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  createdAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  updatedAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
}).strict();

export const BlockchainWalletUncheckedUpdateManyInputSchema: z.ZodType<Prisma.BlockchainWalletUncheckedUpdateManyInput> = z.object({
  id: z.union([ z.string().uuid(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  companyId: z.union([ z.number().int(),z.lazy(() => IntFieldUpdateOperationsInputSchema) ]).optional(),
  address: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  privateKey: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  createdAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  updatedAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
}).strict();

export const ApiKeyCreateInputSchema: z.ZodType<Prisma.ApiKeyCreateInput> = z.object({
  id: z.string().uuid().optional(),
  key: z.string(),
  createdAt: z.coerce.date().optional(),
  updatedAt: z.coerce.date().optional(),
  isActive: z.boolean().optional(),
  isDeleted: z.boolean().optional(),
  isRevoked: z.boolean().optional(),
  lastUsed: z.coerce.date().optional().nullable(),
  company: z.lazy(() => CompanyCreateNestedOneWithoutApiKeyInputSchema),
  user: z.lazy(() => UserCreateNestedManyWithoutApiKeysInputSchema).optional()
}).strict();

export const ApiKeyUncheckedCreateInputSchema: z.ZodType<Prisma.ApiKeyUncheckedCreateInput> = z.object({
  id: z.string().uuid().optional(),
  companyId: z.number().int(),
  key: z.string(),
  createdAt: z.coerce.date().optional(),
  updatedAt: z.coerce.date().optional(),
  isActive: z.boolean().optional(),
  isDeleted: z.boolean().optional(),
  isRevoked: z.boolean().optional(),
  lastUsed: z.coerce.date().optional().nullable(),
  user: z.lazy(() => UserUncheckedCreateNestedManyWithoutApiKeysInputSchema).optional()
}).strict();

export const ApiKeyUpdateInputSchema: z.ZodType<Prisma.ApiKeyUpdateInput> = z.object({
  id: z.union([ z.string().uuid(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  key: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  createdAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  updatedAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  isActive: z.union([ z.boolean(),z.lazy(() => BoolFieldUpdateOperationsInputSchema) ]).optional(),
  isDeleted: z.union([ z.boolean(),z.lazy(() => BoolFieldUpdateOperationsInputSchema) ]).optional(),
  isRevoked: z.union([ z.boolean(),z.lazy(() => BoolFieldUpdateOperationsInputSchema) ]).optional(),
  lastUsed: z.union([ z.coerce.date(),z.lazy(() => NullableDateTimeFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  company: z.lazy(() => CompanyUpdateOneRequiredWithoutApiKeyNestedInputSchema).optional(),
  user: z.lazy(() => UserUpdateManyWithoutApiKeysNestedInputSchema).optional()
}).strict();

export const ApiKeyUncheckedUpdateInputSchema: z.ZodType<Prisma.ApiKeyUncheckedUpdateInput> = z.object({
  id: z.union([ z.string().uuid(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  companyId: z.union([ z.number().int(),z.lazy(() => IntFieldUpdateOperationsInputSchema) ]).optional(),
  key: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  createdAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  updatedAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  isActive: z.union([ z.boolean(),z.lazy(() => BoolFieldUpdateOperationsInputSchema) ]).optional(),
  isDeleted: z.union([ z.boolean(),z.lazy(() => BoolFieldUpdateOperationsInputSchema) ]).optional(),
  isRevoked: z.union([ z.boolean(),z.lazy(() => BoolFieldUpdateOperationsInputSchema) ]).optional(),
  lastUsed: z.union([ z.coerce.date(),z.lazy(() => NullableDateTimeFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  user: z.lazy(() => UserUncheckedUpdateManyWithoutApiKeysNestedInputSchema).optional()
}).strict();

export const ApiKeyCreateManyInputSchema: z.ZodType<Prisma.ApiKeyCreateManyInput> = z.object({
  id: z.string().uuid().optional(),
  companyId: z.number().int(),
  key: z.string(),
  createdAt: z.coerce.date().optional(),
  updatedAt: z.coerce.date().optional(),
  isActive: z.boolean().optional(),
  isDeleted: z.boolean().optional(),
  isRevoked: z.boolean().optional(),
  lastUsed: z.coerce.date().optional().nullable()
}).strict();

export const ApiKeyUpdateManyMutationInputSchema: z.ZodType<Prisma.ApiKeyUpdateManyMutationInput> = z.object({
  id: z.union([ z.string().uuid(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  key: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  createdAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  updatedAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  isActive: z.union([ z.boolean(),z.lazy(() => BoolFieldUpdateOperationsInputSchema) ]).optional(),
  isDeleted: z.union([ z.boolean(),z.lazy(() => BoolFieldUpdateOperationsInputSchema) ]).optional(),
  isRevoked: z.union([ z.boolean(),z.lazy(() => BoolFieldUpdateOperationsInputSchema) ]).optional(),
  lastUsed: z.union([ z.coerce.date(),z.lazy(() => NullableDateTimeFieldUpdateOperationsInputSchema) ]).optional().nullable(),
}).strict();

export const ApiKeyUncheckedUpdateManyInputSchema: z.ZodType<Prisma.ApiKeyUncheckedUpdateManyInput> = z.object({
  id: z.union([ z.string().uuid(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  companyId: z.union([ z.number().int(),z.lazy(() => IntFieldUpdateOperationsInputSchema) ]).optional(),
  key: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  createdAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  updatedAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  isActive: z.union([ z.boolean(),z.lazy(() => BoolFieldUpdateOperationsInputSchema) ]).optional(),
  isDeleted: z.union([ z.boolean(),z.lazy(() => BoolFieldUpdateOperationsInputSchema) ]).optional(),
  isRevoked: z.union([ z.boolean(),z.lazy(() => BoolFieldUpdateOperationsInputSchema) ]).optional(),
  lastUsed: z.union([ z.coerce.date(),z.lazy(() => NullableDateTimeFieldUpdateOperationsInputSchema) ]).optional().nullable(),
}).strict();

export const AuditLogCreateInputSchema: z.ZodType<Prisma.AuditLogCreateInput> = z.object({
  id: z.string().uuid().optional(),
  action: z.string(),
  userId: z.string().optional().nullable(),
  metadata: z.union([ z.lazy(() => NullableJsonNullValueInputSchema),InputJsonValueSchema ]).optional(),
  createdAt: z.coerce.date().optional(),
  document: z.lazy(() => DocumentCreateNestedOneWithoutAuditLogsInputSchema)
}).strict();

export const AuditLogUncheckedCreateInputSchema: z.ZodType<Prisma.AuditLogUncheckedCreateInput> = z.object({
  id: z.string().uuid().optional(),
  documentId: z.string(),
  action: z.string(),
  userId: z.string().optional().nullable(),
  metadata: z.union([ z.lazy(() => NullableJsonNullValueInputSchema),InputJsonValueSchema ]).optional(),
  createdAt: z.coerce.date().optional()
}).strict();

export const AuditLogUpdateInputSchema: z.ZodType<Prisma.AuditLogUpdateInput> = z.object({
  id: z.union([ z.string().uuid(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  action: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  userId: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  metadata: z.union([ z.lazy(() => NullableJsonNullValueInputSchema),InputJsonValueSchema ]).optional(),
  createdAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  document: z.lazy(() => DocumentUpdateOneRequiredWithoutAuditLogsNestedInputSchema).optional()
}).strict();

export const AuditLogUncheckedUpdateInputSchema: z.ZodType<Prisma.AuditLogUncheckedUpdateInput> = z.object({
  id: z.union([ z.string().uuid(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  documentId: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  action: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  userId: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  metadata: z.union([ z.lazy(() => NullableJsonNullValueInputSchema),InputJsonValueSchema ]).optional(),
  createdAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
}).strict();

export const AuditLogCreateManyInputSchema: z.ZodType<Prisma.AuditLogCreateManyInput> = z.object({
  id: z.string().uuid().optional(),
  documentId: z.string(),
  action: z.string(),
  userId: z.string().optional().nullable(),
  metadata: z.union([ z.lazy(() => NullableJsonNullValueInputSchema),InputJsonValueSchema ]).optional(),
  createdAt: z.coerce.date().optional()
}).strict();

export const AuditLogUpdateManyMutationInputSchema: z.ZodType<Prisma.AuditLogUpdateManyMutationInput> = z.object({
  id: z.union([ z.string().uuid(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  action: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  userId: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  metadata: z.union([ z.lazy(() => NullableJsonNullValueInputSchema),InputJsonValueSchema ]).optional(),
  createdAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
}).strict();

export const AuditLogUncheckedUpdateManyInputSchema: z.ZodType<Prisma.AuditLogUncheckedUpdateManyInput> = z.object({
  id: z.union([ z.string().uuid(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  documentId: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  action: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  userId: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  metadata: z.union([ z.lazy(() => NullableJsonNullValueInputSchema),InputJsonValueSchema ]).optional(),
  createdAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
}).strict();

export const StringFilterSchema: z.ZodType<Prisma.StringFilter> = z.object({
  equals: z.string().optional(),
  in: z.string().array().optional(),
  notIn: z.string().array().optional(),
  lt: z.string().optional(),
  lte: z.string().optional(),
  gt: z.string().optional(),
  gte: z.string().optional(),
  contains: z.string().optional(),
  startsWith: z.string().optional(),
  endsWith: z.string().optional(),
  mode: z.lazy(() => QueryModeSchema).optional(),
  not: z.union([ z.string(),z.lazy(() => NestedStringFilterSchema) ]).optional(),
}).strict();

export const IntFilterSchema: z.ZodType<Prisma.IntFilter> = z.object({
  equals: z.number().optional(),
  in: z.number().array().optional(),
  notIn: z.number().array().optional(),
  lt: z.number().optional(),
  lte: z.number().optional(),
  gt: z.number().optional(),
  gte: z.number().optional(),
  not: z.union([ z.number(),z.lazy(() => NestedIntFilterSchema) ]).optional(),
}).strict();

export const EnumUserRoleFilterSchema: z.ZodType<Prisma.EnumUserRoleFilter> = z.object({
  equals: z.lazy(() => UserRoleSchema).optional(),
  in: z.lazy(() => UserRoleSchema).array().optional(),
  notIn: z.lazy(() => UserRoleSchema).array().optional(),
  not: z.union([ z.lazy(() => UserRoleSchema),z.lazy(() => NestedEnumUserRoleFilterSchema) ]).optional(),
}).strict();

export const DateTimeFilterSchema: z.ZodType<Prisma.DateTimeFilter> = z.object({
  equals: z.coerce.date().optional(),
  in: z.coerce.date().array().optional(),
  notIn: z.coerce.date().array().optional(),
  lt: z.coerce.date().optional(),
  lte: z.coerce.date().optional(),
  gt: z.coerce.date().optional(),
  gte: z.coerce.date().optional(),
  not: z.union([ z.coerce.date(),z.lazy(() => NestedDateTimeFilterSchema) ]).optional(),
}).strict();

export const CompanyScalarRelationFilterSchema: z.ZodType<Prisma.CompanyScalarRelationFilter> = z.object({
  is: z.lazy(() => CompanyWhereInputSchema).optional(),
  isNot: z.lazy(() => CompanyWhereInputSchema).optional()
}).strict();

export const DocumentListRelationFilterSchema: z.ZodType<Prisma.DocumentListRelationFilter> = z.object({
  every: z.lazy(() => DocumentWhereInputSchema).optional(),
  some: z.lazy(() => DocumentWhereInputSchema).optional(),
  none: z.lazy(() => DocumentWhereInputSchema).optional()
}).strict();

export const SignatureListRelationFilterSchema: z.ZodType<Prisma.SignatureListRelationFilter> = z.object({
  every: z.lazy(() => SignatureWhereInputSchema).optional(),
  some: z.lazy(() => SignatureWhereInputSchema).optional(),
  none: z.lazy(() => SignatureWhereInputSchema).optional()
}).strict();

export const ApiKeyListRelationFilterSchema: z.ZodType<Prisma.ApiKeyListRelationFilter> = z.object({
  every: z.lazy(() => ApiKeyWhereInputSchema).optional(),
  some: z.lazy(() => ApiKeyWhereInputSchema).optional(),
  none: z.lazy(() => ApiKeyWhereInputSchema).optional()
}).strict();

export const DocumentOrderByRelationAggregateInputSchema: z.ZodType<Prisma.DocumentOrderByRelationAggregateInput> = z.object({
  _count: z.lazy(() => SortOrderSchema).optional()
}).strict();

export const SignatureOrderByRelationAggregateInputSchema: z.ZodType<Prisma.SignatureOrderByRelationAggregateInput> = z.object({
  _count: z.lazy(() => SortOrderSchema).optional()
}).strict();

export const ApiKeyOrderByRelationAggregateInputSchema: z.ZodType<Prisma.ApiKeyOrderByRelationAggregateInput> = z.object({
  _count: z.lazy(() => SortOrderSchema).optional()
}).strict();

export const UserCountOrderByAggregateInputSchema: z.ZodType<Prisma.UserCountOrderByAggregateInput> = z.object({
  id: z.lazy(() => SortOrderSchema).optional(),
  email: z.lazy(() => SortOrderSchema).optional(),
  name: z.lazy(() => SortOrderSchema).optional(),
  companyId: z.lazy(() => SortOrderSchema).optional(),
  role: z.lazy(() => SortOrderSchema).optional(),
  createdAt: z.lazy(() => SortOrderSchema).optional(),
  updatedAt: z.lazy(() => SortOrderSchema).optional()
}).strict();

export const UserAvgOrderByAggregateInputSchema: z.ZodType<Prisma.UserAvgOrderByAggregateInput> = z.object({
  companyId: z.lazy(() => SortOrderSchema).optional()
}).strict();

export const UserMaxOrderByAggregateInputSchema: z.ZodType<Prisma.UserMaxOrderByAggregateInput> = z.object({
  id: z.lazy(() => SortOrderSchema).optional(),
  email: z.lazy(() => SortOrderSchema).optional(),
  name: z.lazy(() => SortOrderSchema).optional(),
  companyId: z.lazy(() => SortOrderSchema).optional(),
  role: z.lazy(() => SortOrderSchema).optional(),
  createdAt: z.lazy(() => SortOrderSchema).optional(),
  updatedAt: z.lazy(() => SortOrderSchema).optional()
}).strict();

export const UserMinOrderByAggregateInputSchema: z.ZodType<Prisma.UserMinOrderByAggregateInput> = z.object({
  id: z.lazy(() => SortOrderSchema).optional(),
  email: z.lazy(() => SortOrderSchema).optional(),
  name: z.lazy(() => SortOrderSchema).optional(),
  companyId: z.lazy(() => SortOrderSchema).optional(),
  role: z.lazy(() => SortOrderSchema).optional(),
  createdAt: z.lazy(() => SortOrderSchema).optional(),
  updatedAt: z.lazy(() => SortOrderSchema).optional()
}).strict();

export const UserSumOrderByAggregateInputSchema: z.ZodType<Prisma.UserSumOrderByAggregateInput> = z.object({
  companyId: z.lazy(() => SortOrderSchema).optional()
}).strict();

export const StringWithAggregatesFilterSchema: z.ZodType<Prisma.StringWithAggregatesFilter> = z.object({
  equals: z.string().optional(),
  in: z.string().array().optional(),
  notIn: z.string().array().optional(),
  lt: z.string().optional(),
  lte: z.string().optional(),
  gt: z.string().optional(),
  gte: z.string().optional(),
  contains: z.string().optional(),
  startsWith: z.string().optional(),
  endsWith: z.string().optional(),
  mode: z.lazy(() => QueryModeSchema).optional(),
  not: z.union([ z.string(),z.lazy(() => NestedStringWithAggregatesFilterSchema) ]).optional(),
  _count: z.lazy(() => NestedIntFilterSchema).optional(),
  _min: z.lazy(() => NestedStringFilterSchema).optional(),
  _max: z.lazy(() => NestedStringFilterSchema).optional()
}).strict();

export const IntWithAggregatesFilterSchema: z.ZodType<Prisma.IntWithAggregatesFilter> = z.object({
  equals: z.number().optional(),
  in: z.number().array().optional(),
  notIn: z.number().array().optional(),
  lt: z.number().optional(),
  lte: z.number().optional(),
  gt: z.number().optional(),
  gte: z.number().optional(),
  not: z.union([ z.number(),z.lazy(() => NestedIntWithAggregatesFilterSchema) ]).optional(),
  _count: z.lazy(() => NestedIntFilterSchema).optional(),
  _avg: z.lazy(() => NestedFloatFilterSchema).optional(),
  _sum: z.lazy(() => NestedIntFilterSchema).optional(),
  _min: z.lazy(() => NestedIntFilterSchema).optional(),
  _max: z.lazy(() => NestedIntFilterSchema).optional()
}).strict();

export const EnumUserRoleWithAggregatesFilterSchema: z.ZodType<Prisma.EnumUserRoleWithAggregatesFilter> = z.object({
  equals: z.lazy(() => UserRoleSchema).optional(),
  in: z.lazy(() => UserRoleSchema).array().optional(),
  notIn: z.lazy(() => UserRoleSchema).array().optional(),
  not: z.union([ z.lazy(() => UserRoleSchema),z.lazy(() => NestedEnumUserRoleWithAggregatesFilterSchema) ]).optional(),
  _count: z.lazy(() => NestedIntFilterSchema).optional(),
  _min: z.lazy(() => NestedEnumUserRoleFilterSchema).optional(),
  _max: z.lazy(() => NestedEnumUserRoleFilterSchema).optional()
}).strict();

export const DateTimeWithAggregatesFilterSchema: z.ZodType<Prisma.DateTimeWithAggregatesFilter> = z.object({
  equals: z.coerce.date().optional(),
  in: z.coerce.date().array().optional(),
  notIn: z.coerce.date().array().optional(),
  lt: z.coerce.date().optional(),
  lte: z.coerce.date().optional(),
  gt: z.coerce.date().optional(),
  gte: z.coerce.date().optional(),
  not: z.union([ z.coerce.date(),z.lazy(() => NestedDateTimeWithAggregatesFilterSchema) ]).optional(),
  _count: z.lazy(() => NestedIntFilterSchema).optional(),
  _min: z.lazy(() => NestedDateTimeFilterSchema).optional(),
  _max: z.lazy(() => NestedDateTimeFilterSchema).optional()
}).strict();

export const StringNullableFilterSchema: z.ZodType<Prisma.StringNullableFilter> = z.object({
  equals: z.string().optional().nullable(),
  in: z.string().array().optional().nullable(),
  notIn: z.string().array().optional().nullable(),
  lt: z.string().optional(),
  lte: z.string().optional(),
  gt: z.string().optional(),
  gte: z.string().optional(),
  contains: z.string().optional(),
  startsWith: z.string().optional(),
  endsWith: z.string().optional(),
  mode: z.lazy(() => QueryModeSchema).optional(),
  not: z.union([ z.string(),z.lazy(() => NestedStringNullableFilterSchema) ]).optional().nullable(),
}).strict();

export const UserListRelationFilterSchema: z.ZodType<Prisma.UserListRelationFilter> = z.object({
  every: z.lazy(() => UserWhereInputSchema).optional(),
  some: z.lazy(() => UserWhereInputSchema).optional(),
  none: z.lazy(() => UserWhereInputSchema).optional()
}).strict();

export const CertificateListRelationFilterSchema: z.ZodType<Prisma.CertificateListRelationFilter> = z.object({
  every: z.lazy(() => CertificateWhereInputSchema).optional(),
  some: z.lazy(() => CertificateWhereInputSchema).optional(),
  none: z.lazy(() => CertificateWhereInputSchema).optional()
}).strict();

export const BlockchainWalletNullableScalarRelationFilterSchema: z.ZodType<Prisma.BlockchainWalletNullableScalarRelationFilter> = z.object({
  is: z.lazy(() => BlockchainWalletWhereInputSchema).optional().nullable(),
  isNot: z.lazy(() => BlockchainWalletWhereInputSchema).optional().nullable()
}).strict();

export const SigningTemplateListRelationFilterSchema: z.ZodType<Prisma.SigningTemplateListRelationFilter> = z.object({
  every: z.lazy(() => SigningTemplateWhereInputSchema).optional(),
  some: z.lazy(() => SigningTemplateWhereInputSchema).optional(),
  none: z.lazy(() => SigningTemplateWhereInputSchema).optional()
}).strict();

export const SortOrderInputSchema: z.ZodType<Prisma.SortOrderInput> = z.object({
  sort: z.lazy(() => SortOrderSchema),
  nulls: z.lazy(() => NullsOrderSchema).optional()
}).strict();

export const UserOrderByRelationAggregateInputSchema: z.ZodType<Prisma.UserOrderByRelationAggregateInput> = z.object({
  _count: z.lazy(() => SortOrderSchema).optional()
}).strict();

export const CertificateOrderByRelationAggregateInputSchema: z.ZodType<Prisma.CertificateOrderByRelationAggregateInput> = z.object({
  _count: z.lazy(() => SortOrderSchema).optional()
}).strict();

export const SigningTemplateOrderByRelationAggregateInputSchema: z.ZodType<Prisma.SigningTemplateOrderByRelationAggregateInput> = z.object({
  _count: z.lazy(() => SortOrderSchema).optional()
}).strict();

export const CompanyCountOrderByAggregateInputSchema: z.ZodType<Prisma.CompanyCountOrderByAggregateInput> = z.object({
  id: z.lazy(() => SortOrderSchema).optional(),
  name: z.lazy(() => SortOrderSchema).optional(),
  adminEmail: z.lazy(() => SortOrderSchema).optional(),
  country: z.lazy(() => SortOrderSchema).optional(),
  rootCertificate: z.lazy(() => SortOrderSchema).optional(),
  subscriptionId: z.lazy(() => SortOrderSchema).optional(),
  createdAt: z.lazy(() => SortOrderSchema).optional(),
  updatedAt: z.lazy(() => SortOrderSchema).optional()
}).strict();

export const CompanyAvgOrderByAggregateInputSchema: z.ZodType<Prisma.CompanyAvgOrderByAggregateInput> = z.object({
  id: z.lazy(() => SortOrderSchema).optional()
}).strict();

export const CompanyMaxOrderByAggregateInputSchema: z.ZodType<Prisma.CompanyMaxOrderByAggregateInput> = z.object({
  id: z.lazy(() => SortOrderSchema).optional(),
  name: z.lazy(() => SortOrderSchema).optional(),
  adminEmail: z.lazy(() => SortOrderSchema).optional(),
  country: z.lazy(() => SortOrderSchema).optional(),
  rootCertificate: z.lazy(() => SortOrderSchema).optional(),
  subscriptionId: z.lazy(() => SortOrderSchema).optional(),
  createdAt: z.lazy(() => SortOrderSchema).optional(),
  updatedAt: z.lazy(() => SortOrderSchema).optional()
}).strict();

export const CompanyMinOrderByAggregateInputSchema: z.ZodType<Prisma.CompanyMinOrderByAggregateInput> = z.object({
  id: z.lazy(() => SortOrderSchema).optional(),
  name: z.lazy(() => SortOrderSchema).optional(),
  adminEmail: z.lazy(() => SortOrderSchema).optional(),
  country: z.lazy(() => SortOrderSchema).optional(),
  rootCertificate: z.lazy(() => SortOrderSchema).optional(),
  subscriptionId: z.lazy(() => SortOrderSchema).optional(),
  createdAt: z.lazy(() => SortOrderSchema).optional(),
  updatedAt: z.lazy(() => SortOrderSchema).optional()
}).strict();

export const CompanySumOrderByAggregateInputSchema: z.ZodType<Prisma.CompanySumOrderByAggregateInput> = z.object({
  id: z.lazy(() => SortOrderSchema).optional()
}).strict();

export const StringNullableWithAggregatesFilterSchema: z.ZodType<Prisma.StringNullableWithAggregatesFilter> = z.object({
  equals: z.string().optional().nullable(),
  in: z.string().array().optional().nullable(),
  notIn: z.string().array().optional().nullable(),
  lt: z.string().optional(),
  lte: z.string().optional(),
  gt: z.string().optional(),
  gte: z.string().optional(),
  contains: z.string().optional(),
  startsWith: z.string().optional(),
  endsWith: z.string().optional(),
  mode: z.lazy(() => QueryModeSchema).optional(),
  not: z.union([ z.string(),z.lazy(() => NestedStringNullableWithAggregatesFilterSchema) ]).optional().nullable(),
  _count: z.lazy(() => NestedIntNullableFilterSchema).optional(),
  _min: z.lazy(() => NestedStringNullableFilterSchema).optional(),
  _max: z.lazy(() => NestedStringNullableFilterSchema).optional()
}).strict();

export const EnumDocumentStatusFilterSchema: z.ZodType<Prisma.EnumDocumentStatusFilter> = z.object({
  equals: z.lazy(() => DocumentStatusSchema).optional(),
  in: z.lazy(() => DocumentStatusSchema).array().optional(),
  notIn: z.lazy(() => DocumentStatusSchema).array().optional(),
  not: z.union([ z.lazy(() => DocumentStatusSchema),z.lazy(() => NestedEnumDocumentStatusFilterSchema) ]).optional(),
}).strict();

export const JsonNullableFilterSchema: z.ZodType<Prisma.JsonNullableFilter> = z.object({
  equals: InputJsonValueSchema.optional(),
  path: z.string().array().optional(),
  string_contains: z.string().optional(),
  string_starts_with: z.string().optional(),
  string_ends_with: z.string().optional(),
  array_starts_with: InputJsonValueSchema.optional().nullable(),
  array_ends_with: InputJsonValueSchema.optional().nullable(),
  array_contains: InputJsonValueSchema.optional().nullable(),
  lt: InputJsonValueSchema.optional(),
  lte: InputJsonValueSchema.optional(),
  gt: InputJsonValueSchema.optional(),
  gte: InputJsonValueSchema.optional(),
  not: InputJsonValueSchema.optional()
}).strict();

export const DateTimeNullableFilterSchema: z.ZodType<Prisma.DateTimeNullableFilter> = z.object({
  equals: z.coerce.date().optional().nullable(),
  in: z.coerce.date().array().optional().nullable(),
  notIn: z.coerce.date().array().optional().nullable(),
  lt: z.coerce.date().optional(),
  lte: z.coerce.date().optional(),
  gt: z.coerce.date().optional(),
  gte: z.coerce.date().optional(),
  not: z.union([ z.coerce.date(),z.lazy(() => NestedDateTimeNullableFilterSchema) ]).optional().nullable(),
}).strict();

export const UserScalarRelationFilterSchema: z.ZodType<Prisma.UserScalarRelationFilter> = z.object({
  is: z.lazy(() => UserWhereInputSchema).optional(),
  isNot: z.lazy(() => UserWhereInputSchema).optional()
}).strict();

export const SigningTemplateNullableScalarRelationFilterSchema: z.ZodType<Prisma.SigningTemplateNullableScalarRelationFilter> = z.object({
  is: z.lazy(() => SigningTemplateWhereInputSchema).optional().nullable(),
  isNot: z.lazy(() => SigningTemplateWhereInputSchema).optional().nullable()
}).strict();

export const DocumentSignerListRelationFilterSchema: z.ZodType<Prisma.DocumentSignerListRelationFilter> = z.object({
  every: z.lazy(() => DocumentSignerWhereInputSchema).optional(),
  some: z.lazy(() => DocumentSignerWhereInputSchema).optional(),
  none: z.lazy(() => DocumentSignerWhereInputSchema).optional()
}).strict();

export const AuditLogListRelationFilterSchema: z.ZodType<Prisma.AuditLogListRelationFilter> = z.object({
  every: z.lazy(() => AuditLogWhereInputSchema).optional(),
  some: z.lazy(() => AuditLogWhereInputSchema).optional(),
  none: z.lazy(() => AuditLogWhereInputSchema).optional()
}).strict();

export const SignatureFieldListRelationFilterSchema: z.ZodType<Prisma.SignatureFieldListRelationFilter> = z.object({
  every: z.lazy(() => SignatureFieldWhereInputSchema).optional(),
  some: z.lazy(() => SignatureFieldWhereInputSchema).optional(),
  none: z.lazy(() => SignatureFieldWhereInputSchema).optional()
}).strict();

export const DocumentSignerOrderByRelationAggregateInputSchema: z.ZodType<Prisma.DocumentSignerOrderByRelationAggregateInput> = z.object({
  _count: z.lazy(() => SortOrderSchema).optional()
}).strict();

export const AuditLogOrderByRelationAggregateInputSchema: z.ZodType<Prisma.AuditLogOrderByRelationAggregateInput> = z.object({
  _count: z.lazy(() => SortOrderSchema).optional()
}).strict();

export const SignatureFieldOrderByRelationAggregateInputSchema: z.ZodType<Prisma.SignatureFieldOrderByRelationAggregateInput> = z.object({
  _count: z.lazy(() => SortOrderSchema).optional()
}).strict();

export const DocumentCountOrderByAggregateInputSchema: z.ZodType<Prisma.DocumentCountOrderByAggregateInput> = z.object({
  id: z.lazy(() => SortOrderSchema).optional(),
  title: z.lazy(() => SortOrderSchema).optional(),
  description: z.lazy(() => SortOrderSchema).optional(),
  userId: z.lazy(() => SortOrderSchema).optional(),
  companyId: z.lazy(() => SortOrderSchema).optional(),
  status: z.lazy(() => SortOrderSchema).optional(),
  fileUrl: z.lazy(() => SortOrderSchema).optional(),
  fileHash: z.lazy(() => SortOrderSchema).optional(),
  blockchainDocId: z.lazy(() => SortOrderSchema).optional(),
  templateId: z.lazy(() => SortOrderSchema).optional(),
  metadata: z.lazy(() => SortOrderSchema).optional(),
  expiresAt: z.lazy(() => SortOrderSchema).optional(),
  createdAt: z.lazy(() => SortOrderSchema).optional(),
  updatedAt: z.lazy(() => SortOrderSchema).optional()
}).strict();

export const DocumentAvgOrderByAggregateInputSchema: z.ZodType<Prisma.DocumentAvgOrderByAggregateInput> = z.object({
  companyId: z.lazy(() => SortOrderSchema).optional()
}).strict();

export const DocumentMaxOrderByAggregateInputSchema: z.ZodType<Prisma.DocumentMaxOrderByAggregateInput> = z.object({
  id: z.lazy(() => SortOrderSchema).optional(),
  title: z.lazy(() => SortOrderSchema).optional(),
  description: z.lazy(() => SortOrderSchema).optional(),
  userId: z.lazy(() => SortOrderSchema).optional(),
  companyId: z.lazy(() => SortOrderSchema).optional(),
  status: z.lazy(() => SortOrderSchema).optional(),
  fileUrl: z.lazy(() => SortOrderSchema).optional(),
  fileHash: z.lazy(() => SortOrderSchema).optional(),
  blockchainDocId: z.lazy(() => SortOrderSchema).optional(),
  templateId: z.lazy(() => SortOrderSchema).optional(),
  expiresAt: z.lazy(() => SortOrderSchema).optional(),
  createdAt: z.lazy(() => SortOrderSchema).optional(),
  updatedAt: z.lazy(() => SortOrderSchema).optional()
}).strict();

export const DocumentMinOrderByAggregateInputSchema: z.ZodType<Prisma.DocumentMinOrderByAggregateInput> = z.object({
  id: z.lazy(() => SortOrderSchema).optional(),
  title: z.lazy(() => SortOrderSchema).optional(),
  description: z.lazy(() => SortOrderSchema).optional(),
  userId: z.lazy(() => SortOrderSchema).optional(),
  companyId: z.lazy(() => SortOrderSchema).optional(),
  status: z.lazy(() => SortOrderSchema).optional(),
  fileUrl: z.lazy(() => SortOrderSchema).optional(),
  fileHash: z.lazy(() => SortOrderSchema).optional(),
  blockchainDocId: z.lazy(() => SortOrderSchema).optional(),
  templateId: z.lazy(() => SortOrderSchema).optional(),
  expiresAt: z.lazy(() => SortOrderSchema).optional(),
  createdAt: z.lazy(() => SortOrderSchema).optional(),
  updatedAt: z.lazy(() => SortOrderSchema).optional()
}).strict();

export const DocumentSumOrderByAggregateInputSchema: z.ZodType<Prisma.DocumentSumOrderByAggregateInput> = z.object({
  companyId: z.lazy(() => SortOrderSchema).optional()
}).strict();

export const EnumDocumentStatusWithAggregatesFilterSchema: z.ZodType<Prisma.EnumDocumentStatusWithAggregatesFilter> = z.object({
  equals: z.lazy(() => DocumentStatusSchema).optional(),
  in: z.lazy(() => DocumentStatusSchema).array().optional(),
  notIn: z.lazy(() => DocumentStatusSchema).array().optional(),
  not: z.union([ z.lazy(() => DocumentStatusSchema),z.lazy(() => NestedEnumDocumentStatusWithAggregatesFilterSchema) ]).optional(),
  _count: z.lazy(() => NestedIntFilterSchema).optional(),
  _min: z.lazy(() => NestedEnumDocumentStatusFilterSchema).optional(),
  _max: z.lazy(() => NestedEnumDocumentStatusFilterSchema).optional()
}).strict();

export const JsonNullableWithAggregatesFilterSchema: z.ZodType<Prisma.JsonNullableWithAggregatesFilter> = z.object({
  equals: InputJsonValueSchema.optional(),
  path: z.string().array().optional(),
  string_contains: z.string().optional(),
  string_starts_with: z.string().optional(),
  string_ends_with: z.string().optional(),
  array_starts_with: InputJsonValueSchema.optional().nullable(),
  array_ends_with: InputJsonValueSchema.optional().nullable(),
  array_contains: InputJsonValueSchema.optional().nullable(),
  lt: InputJsonValueSchema.optional(),
  lte: InputJsonValueSchema.optional(),
  gt: InputJsonValueSchema.optional(),
  gte: InputJsonValueSchema.optional(),
  not: InputJsonValueSchema.optional(),
  _count: z.lazy(() => NestedIntNullableFilterSchema).optional(),
  _min: z.lazy(() => NestedJsonNullableFilterSchema).optional(),
  _max: z.lazy(() => NestedJsonNullableFilterSchema).optional()
}).strict();

export const DateTimeNullableWithAggregatesFilterSchema: z.ZodType<Prisma.DateTimeNullableWithAggregatesFilter> = z.object({
  equals: z.coerce.date().optional().nullable(),
  in: z.coerce.date().array().optional().nullable(),
  notIn: z.coerce.date().array().optional().nullable(),
  lt: z.coerce.date().optional(),
  lte: z.coerce.date().optional(),
  gt: z.coerce.date().optional(),
  gte: z.coerce.date().optional(),
  not: z.union([ z.coerce.date(),z.lazy(() => NestedDateTimeNullableWithAggregatesFilterSchema) ]).optional().nullable(),
  _count: z.lazy(() => NestedIntNullableFilterSchema).optional(),
  _min: z.lazy(() => NestedDateTimeNullableFilterSchema).optional(),
  _max: z.lazy(() => NestedDateTimeNullableFilterSchema).optional()
}).strict();

export const EnumSignerStatusFilterSchema: z.ZodType<Prisma.EnumSignerStatusFilter> = z.object({
  equals: z.lazy(() => SignerStatusSchema).optional(),
  in: z.lazy(() => SignerStatusSchema).array().optional(),
  notIn: z.lazy(() => SignerStatusSchema).array().optional(),
  not: z.union([ z.lazy(() => SignerStatusSchema),z.lazy(() => NestedEnumSignerStatusFilterSchema) ]).optional(),
}).strict();

export const DocumentScalarRelationFilterSchema: z.ZodType<Prisma.DocumentScalarRelationFilter> = z.object({
  is: z.lazy(() => DocumentWhereInputSchema).optional(),
  isNot: z.lazy(() => DocumentWhereInputSchema).optional()
}).strict();

export const SignatureNullableScalarRelationFilterSchema: z.ZodType<Prisma.SignatureNullableScalarRelationFilter> = z.object({
  is: z.lazy(() => SignatureWhereInputSchema).optional().nullable(),
  isNot: z.lazy(() => SignatureWhereInputSchema).optional().nullable()
}).strict();

export const DocumentSignerCountOrderByAggregateInputSchema: z.ZodType<Prisma.DocumentSignerCountOrderByAggregateInput> = z.object({
  id: z.lazy(() => SortOrderSchema).optional(),
  documentId: z.lazy(() => SortOrderSchema).optional(),
  email: z.lazy(() => SortOrderSchema).optional(),
  name: z.lazy(() => SortOrderSchema).optional(),
  order: z.lazy(() => SortOrderSchema).optional(),
  status: z.lazy(() => SortOrderSchema).optional(),
  expiresAt: z.lazy(() => SortOrderSchema).optional(),
  notifiedAt: z.lazy(() => SortOrderSchema).optional(),
  createdAt: z.lazy(() => SortOrderSchema).optional(),
  updatedAt: z.lazy(() => SortOrderSchema).optional(),
  signatureId: z.lazy(() => SortOrderSchema).optional()
}).strict();

export const DocumentSignerAvgOrderByAggregateInputSchema: z.ZodType<Prisma.DocumentSignerAvgOrderByAggregateInput> = z.object({
  order: z.lazy(() => SortOrderSchema).optional()
}).strict();

export const DocumentSignerMaxOrderByAggregateInputSchema: z.ZodType<Prisma.DocumentSignerMaxOrderByAggregateInput> = z.object({
  id: z.lazy(() => SortOrderSchema).optional(),
  documentId: z.lazy(() => SortOrderSchema).optional(),
  email: z.lazy(() => SortOrderSchema).optional(),
  name: z.lazy(() => SortOrderSchema).optional(),
  order: z.lazy(() => SortOrderSchema).optional(),
  status: z.lazy(() => SortOrderSchema).optional(),
  expiresAt: z.lazy(() => SortOrderSchema).optional(),
  notifiedAt: z.lazy(() => SortOrderSchema).optional(),
  createdAt: z.lazy(() => SortOrderSchema).optional(),
  updatedAt: z.lazy(() => SortOrderSchema).optional(),
  signatureId: z.lazy(() => SortOrderSchema).optional()
}).strict();

export const DocumentSignerMinOrderByAggregateInputSchema: z.ZodType<Prisma.DocumentSignerMinOrderByAggregateInput> = z.object({
  id: z.lazy(() => SortOrderSchema).optional(),
  documentId: z.lazy(() => SortOrderSchema).optional(),
  email: z.lazy(() => SortOrderSchema).optional(),
  name: z.lazy(() => SortOrderSchema).optional(),
  order: z.lazy(() => SortOrderSchema).optional(),
  status: z.lazy(() => SortOrderSchema).optional(),
  expiresAt: z.lazy(() => SortOrderSchema).optional(),
  notifiedAt: z.lazy(() => SortOrderSchema).optional(),
  createdAt: z.lazy(() => SortOrderSchema).optional(),
  updatedAt: z.lazy(() => SortOrderSchema).optional(),
  signatureId: z.lazy(() => SortOrderSchema).optional()
}).strict();

export const DocumentSignerSumOrderByAggregateInputSchema: z.ZodType<Prisma.DocumentSignerSumOrderByAggregateInput> = z.object({
  order: z.lazy(() => SortOrderSchema).optional()
}).strict();

export const EnumSignerStatusWithAggregatesFilterSchema: z.ZodType<Prisma.EnumSignerStatusWithAggregatesFilter> = z.object({
  equals: z.lazy(() => SignerStatusSchema).optional(),
  in: z.lazy(() => SignerStatusSchema).array().optional(),
  notIn: z.lazy(() => SignerStatusSchema).array().optional(),
  not: z.union([ z.lazy(() => SignerStatusSchema),z.lazy(() => NestedEnumSignerStatusWithAggregatesFilterSchema) ]).optional(),
  _count: z.lazy(() => NestedIntFilterSchema).optional(),
  _min: z.lazy(() => NestedEnumSignerStatusFilterSchema).optional(),
  _max: z.lazy(() => NestedEnumSignerStatusFilterSchema).optional()
}).strict();

export const EnumFieldTypeFilterSchema: z.ZodType<Prisma.EnumFieldTypeFilter> = z.object({
  equals: z.lazy(() => FieldTypeSchema).optional(),
  in: z.lazy(() => FieldTypeSchema).array().optional(),
  notIn: z.lazy(() => FieldTypeSchema).array().optional(),
  not: z.union([ z.lazy(() => FieldTypeSchema),z.lazy(() => NestedEnumFieldTypeFilterSchema) ]).optional(),
}).strict();

export const BoolFilterSchema: z.ZodType<Prisma.BoolFilter> = z.object({
  equals: z.boolean().optional(),
  not: z.union([ z.boolean(),z.lazy(() => NestedBoolFilterSchema) ]).optional(),
}).strict();

export const FloatFilterSchema: z.ZodType<Prisma.FloatFilter> = z.object({
  equals: z.number().optional(),
  in: z.number().array().optional(),
  notIn: z.number().array().optional(),
  lt: z.number().optional(),
  lte: z.number().optional(),
  gt: z.number().optional(),
  gte: z.number().optional(),
  not: z.union([ z.number(),z.lazy(() => NestedFloatFilterSchema) ]).optional(),
}).strict();

export const DocumentSignerScalarRelationFilterSchema: z.ZodType<Prisma.DocumentSignerScalarRelationFilter> = z.object({
  is: z.lazy(() => DocumentSignerWhereInputSchema).optional(),
  isNot: z.lazy(() => DocumentSignerWhereInputSchema).optional()
}).strict();

export const SignatureFieldCountOrderByAggregateInputSchema: z.ZodType<Prisma.SignatureFieldCountOrderByAggregateInput> = z.object({
  id: z.lazy(() => SortOrderSchema).optional(),
  documentId: z.lazy(() => SortOrderSchema).optional(),
  signerId: z.lazy(() => SortOrderSchema).optional(),
  type: z.lazy(() => SortOrderSchema).optional(),
  required: z.lazy(() => SortOrderSchema).optional(),
  page: z.lazy(() => SortOrderSchema).optional(),
  x: z.lazy(() => SortOrderSchema).optional(),
  y: z.lazy(() => SortOrderSchema).optional(),
  width: z.lazy(() => SortOrderSchema).optional(),
  height: z.lazy(() => SortOrderSchema).optional(),
  signedAt: z.lazy(() => SortOrderSchema).optional(),
  createdAt: z.lazy(() => SortOrderSchema).optional(),
  updatedAt: z.lazy(() => SortOrderSchema).optional()
}).strict();

export const SignatureFieldAvgOrderByAggregateInputSchema: z.ZodType<Prisma.SignatureFieldAvgOrderByAggregateInput> = z.object({
  page: z.lazy(() => SortOrderSchema).optional(),
  x: z.lazy(() => SortOrderSchema).optional(),
  y: z.lazy(() => SortOrderSchema).optional(),
  width: z.lazy(() => SortOrderSchema).optional(),
  height: z.lazy(() => SortOrderSchema).optional()
}).strict();

export const SignatureFieldMaxOrderByAggregateInputSchema: z.ZodType<Prisma.SignatureFieldMaxOrderByAggregateInput> = z.object({
  id: z.lazy(() => SortOrderSchema).optional(),
  documentId: z.lazy(() => SortOrderSchema).optional(),
  signerId: z.lazy(() => SortOrderSchema).optional(),
  type: z.lazy(() => SortOrderSchema).optional(),
  required: z.lazy(() => SortOrderSchema).optional(),
  page: z.lazy(() => SortOrderSchema).optional(),
  x: z.lazy(() => SortOrderSchema).optional(),
  y: z.lazy(() => SortOrderSchema).optional(),
  width: z.lazy(() => SortOrderSchema).optional(),
  height: z.lazy(() => SortOrderSchema).optional(),
  signedAt: z.lazy(() => SortOrderSchema).optional(),
  createdAt: z.lazy(() => SortOrderSchema).optional(),
  updatedAt: z.lazy(() => SortOrderSchema).optional()
}).strict();

export const SignatureFieldMinOrderByAggregateInputSchema: z.ZodType<Prisma.SignatureFieldMinOrderByAggregateInput> = z.object({
  id: z.lazy(() => SortOrderSchema).optional(),
  documentId: z.lazy(() => SortOrderSchema).optional(),
  signerId: z.lazy(() => SortOrderSchema).optional(),
  type: z.lazy(() => SortOrderSchema).optional(),
  required: z.lazy(() => SortOrderSchema).optional(),
  page: z.lazy(() => SortOrderSchema).optional(),
  x: z.lazy(() => SortOrderSchema).optional(),
  y: z.lazy(() => SortOrderSchema).optional(),
  width: z.lazy(() => SortOrderSchema).optional(),
  height: z.lazy(() => SortOrderSchema).optional(),
  signedAt: z.lazy(() => SortOrderSchema).optional(),
  createdAt: z.lazy(() => SortOrderSchema).optional(),
  updatedAt: z.lazy(() => SortOrderSchema).optional()
}).strict();

export const SignatureFieldSumOrderByAggregateInputSchema: z.ZodType<Prisma.SignatureFieldSumOrderByAggregateInput> = z.object({
  page: z.lazy(() => SortOrderSchema).optional(),
  x: z.lazy(() => SortOrderSchema).optional(),
  y: z.lazy(() => SortOrderSchema).optional(),
  width: z.lazy(() => SortOrderSchema).optional(),
  height: z.lazy(() => SortOrderSchema).optional()
}).strict();

export const EnumFieldTypeWithAggregatesFilterSchema: z.ZodType<Prisma.EnumFieldTypeWithAggregatesFilter> = z.object({
  equals: z.lazy(() => FieldTypeSchema).optional(),
  in: z.lazy(() => FieldTypeSchema).array().optional(),
  notIn: z.lazy(() => FieldTypeSchema).array().optional(),
  not: z.union([ z.lazy(() => FieldTypeSchema),z.lazy(() => NestedEnumFieldTypeWithAggregatesFilterSchema) ]).optional(),
  _count: z.lazy(() => NestedIntFilterSchema).optional(),
  _min: z.lazy(() => NestedEnumFieldTypeFilterSchema).optional(),
  _max: z.lazy(() => NestedEnumFieldTypeFilterSchema).optional()
}).strict();

export const BoolWithAggregatesFilterSchema: z.ZodType<Prisma.BoolWithAggregatesFilter> = z.object({
  equals: z.boolean().optional(),
  not: z.union([ z.boolean(),z.lazy(() => NestedBoolWithAggregatesFilterSchema) ]).optional(),
  _count: z.lazy(() => NestedIntFilterSchema).optional(),
  _min: z.lazy(() => NestedBoolFilterSchema).optional(),
  _max: z.lazy(() => NestedBoolFilterSchema).optional()
}).strict();

export const FloatWithAggregatesFilterSchema: z.ZodType<Prisma.FloatWithAggregatesFilter> = z.object({
  equals: z.number().optional(),
  in: z.number().array().optional(),
  notIn: z.number().array().optional(),
  lt: z.number().optional(),
  lte: z.number().optional(),
  gt: z.number().optional(),
  gte: z.number().optional(),
  not: z.union([ z.number(),z.lazy(() => NestedFloatWithAggregatesFilterSchema) ]).optional(),
  _count: z.lazy(() => NestedIntFilterSchema).optional(),
  _avg: z.lazy(() => NestedFloatFilterSchema).optional(),
  _sum: z.lazy(() => NestedFloatFilterSchema).optional(),
  _min: z.lazy(() => NestedFloatFilterSchema).optional(),
  _max: z.lazy(() => NestedFloatFilterSchema).optional()
}).strict();

export const CertificateScalarRelationFilterSchema: z.ZodType<Prisma.CertificateScalarRelationFilter> = z.object({
  is: z.lazy(() => CertificateWhereInputSchema).optional(),
  isNot: z.lazy(() => CertificateWhereInputSchema).optional()
}).strict();

export const SignatureCountOrderByAggregateInputSchema: z.ZodType<Prisma.SignatureCountOrderByAggregateInput> = z.object({
  id: z.lazy(() => SortOrderSchema).optional(),
  documentId: z.lazy(() => SortOrderSchema).optional(),
  userId: z.lazy(() => SortOrderSchema).optional(),
  certificateId: z.lazy(() => SortOrderSchema).optional(),
  signatureData: z.lazy(() => SortOrderSchema).optional(),
  visualSignature: z.lazy(() => SortOrderSchema).optional(),
  blockchainTx: z.lazy(() => SortOrderSchema).optional(),
  coordinates: z.lazy(() => SortOrderSchema).optional(),
  metadata: z.lazy(() => SortOrderSchema).optional(),
  createdAt: z.lazy(() => SortOrderSchema).optional(),
  updatedAt: z.lazy(() => SortOrderSchema).optional()
}).strict();

export const SignatureMaxOrderByAggregateInputSchema: z.ZodType<Prisma.SignatureMaxOrderByAggregateInput> = z.object({
  id: z.lazy(() => SortOrderSchema).optional(),
  documentId: z.lazy(() => SortOrderSchema).optional(),
  userId: z.lazy(() => SortOrderSchema).optional(),
  certificateId: z.lazy(() => SortOrderSchema).optional(),
  signatureData: z.lazy(() => SortOrderSchema).optional(),
  visualSignature: z.lazy(() => SortOrderSchema).optional(),
  blockchainTx: z.lazy(() => SortOrderSchema).optional(),
  createdAt: z.lazy(() => SortOrderSchema).optional(),
  updatedAt: z.lazy(() => SortOrderSchema).optional()
}).strict();

export const SignatureMinOrderByAggregateInputSchema: z.ZodType<Prisma.SignatureMinOrderByAggregateInput> = z.object({
  id: z.lazy(() => SortOrderSchema).optional(),
  documentId: z.lazy(() => SortOrderSchema).optional(),
  userId: z.lazy(() => SortOrderSchema).optional(),
  certificateId: z.lazy(() => SortOrderSchema).optional(),
  signatureData: z.lazy(() => SortOrderSchema).optional(),
  visualSignature: z.lazy(() => SortOrderSchema).optional(),
  blockchainTx: z.lazy(() => SortOrderSchema).optional(),
  createdAt: z.lazy(() => SortOrderSchema).optional(),
  updatedAt: z.lazy(() => SortOrderSchema).optional()
}).strict();

export const CertificateCountOrderByAggregateInputSchema: z.ZodType<Prisma.CertificateCountOrderByAggregateInput> = z.object({
  id: z.lazy(() => SortOrderSchema).optional(),
  companyId: z.lazy(() => SortOrderSchema).optional(),
  fingerprint: z.lazy(() => SortOrderSchema).optional(),
  publicKey: z.lazy(() => SortOrderSchema).optional(),
  privateKey: z.lazy(() => SortOrderSchema).optional(),
  isCA: z.lazy(() => SortOrderSchema).optional(),
  issuerCertId: z.lazy(() => SortOrderSchema).optional(),
  validFrom: z.lazy(() => SortOrderSchema).optional(),
  validTo: z.lazy(() => SortOrderSchema).optional(),
  metadata: z.lazy(() => SortOrderSchema).optional(),
  createdAt: z.lazy(() => SortOrderSchema).optional(),
  updatedAt: z.lazy(() => SortOrderSchema).optional()
}).strict();

export const CertificateAvgOrderByAggregateInputSchema: z.ZodType<Prisma.CertificateAvgOrderByAggregateInput> = z.object({
  companyId: z.lazy(() => SortOrderSchema).optional()
}).strict();

export const CertificateMaxOrderByAggregateInputSchema: z.ZodType<Prisma.CertificateMaxOrderByAggregateInput> = z.object({
  id: z.lazy(() => SortOrderSchema).optional(),
  companyId: z.lazy(() => SortOrderSchema).optional(),
  fingerprint: z.lazy(() => SortOrderSchema).optional(),
  publicKey: z.lazy(() => SortOrderSchema).optional(),
  privateKey: z.lazy(() => SortOrderSchema).optional(),
  isCA: z.lazy(() => SortOrderSchema).optional(),
  issuerCertId: z.lazy(() => SortOrderSchema).optional(),
  validFrom: z.lazy(() => SortOrderSchema).optional(),
  validTo: z.lazy(() => SortOrderSchema).optional(),
  createdAt: z.lazy(() => SortOrderSchema).optional(),
  updatedAt: z.lazy(() => SortOrderSchema).optional()
}).strict();

export const CertificateMinOrderByAggregateInputSchema: z.ZodType<Prisma.CertificateMinOrderByAggregateInput> = z.object({
  id: z.lazy(() => SortOrderSchema).optional(),
  companyId: z.lazy(() => SortOrderSchema).optional(),
  fingerprint: z.lazy(() => SortOrderSchema).optional(),
  publicKey: z.lazy(() => SortOrderSchema).optional(),
  privateKey: z.lazy(() => SortOrderSchema).optional(),
  isCA: z.lazy(() => SortOrderSchema).optional(),
  issuerCertId: z.lazy(() => SortOrderSchema).optional(),
  validFrom: z.lazy(() => SortOrderSchema).optional(),
  validTo: z.lazy(() => SortOrderSchema).optional(),
  createdAt: z.lazy(() => SortOrderSchema).optional(),
  updatedAt: z.lazy(() => SortOrderSchema).optional()
}).strict();

export const CertificateSumOrderByAggregateInputSchema: z.ZodType<Prisma.CertificateSumOrderByAggregateInput> = z.object({
  companyId: z.lazy(() => SortOrderSchema).optional()
}).strict();

export const JsonFilterSchema: z.ZodType<Prisma.JsonFilter> = z.object({
  equals: InputJsonValueSchema.optional(),
  path: z.string().array().optional(),
  string_contains: z.string().optional(),
  string_starts_with: z.string().optional(),
  string_ends_with: z.string().optional(),
  array_starts_with: InputJsonValueSchema.optional().nullable(),
  array_ends_with: InputJsonValueSchema.optional().nullable(),
  array_contains: InputJsonValueSchema.optional().nullable(),
  lt: InputJsonValueSchema.optional(),
  lte: InputJsonValueSchema.optional(),
  gt: InputJsonValueSchema.optional(),
  gte: InputJsonValueSchema.optional(),
  not: InputJsonValueSchema.optional()
}).strict();

export const SigningTemplateCountOrderByAggregateInputSchema: z.ZodType<Prisma.SigningTemplateCountOrderByAggregateInput> = z.object({
  id: z.lazy(() => SortOrderSchema).optional(),
  name: z.lazy(() => SortOrderSchema).optional(),
  companyId: z.lazy(() => SortOrderSchema).optional(),
  fields: z.lazy(() => SortOrderSchema).optional(),
  createdAt: z.lazy(() => SortOrderSchema).optional(),
  updatedAt: z.lazy(() => SortOrderSchema).optional()
}).strict();

export const SigningTemplateAvgOrderByAggregateInputSchema: z.ZodType<Prisma.SigningTemplateAvgOrderByAggregateInput> = z.object({
  companyId: z.lazy(() => SortOrderSchema).optional()
}).strict();

export const SigningTemplateMaxOrderByAggregateInputSchema: z.ZodType<Prisma.SigningTemplateMaxOrderByAggregateInput> = z.object({
  id: z.lazy(() => SortOrderSchema).optional(),
  name: z.lazy(() => SortOrderSchema).optional(),
  companyId: z.lazy(() => SortOrderSchema).optional(),
  createdAt: z.lazy(() => SortOrderSchema).optional(),
  updatedAt: z.lazy(() => SortOrderSchema).optional()
}).strict();

export const SigningTemplateMinOrderByAggregateInputSchema: z.ZodType<Prisma.SigningTemplateMinOrderByAggregateInput> = z.object({
  id: z.lazy(() => SortOrderSchema).optional(),
  name: z.lazy(() => SortOrderSchema).optional(),
  companyId: z.lazy(() => SortOrderSchema).optional(),
  createdAt: z.lazy(() => SortOrderSchema).optional(),
  updatedAt: z.lazy(() => SortOrderSchema).optional()
}).strict();

export const SigningTemplateSumOrderByAggregateInputSchema: z.ZodType<Prisma.SigningTemplateSumOrderByAggregateInput> = z.object({
  companyId: z.lazy(() => SortOrderSchema).optional()
}).strict();

export const JsonWithAggregatesFilterSchema: z.ZodType<Prisma.JsonWithAggregatesFilter> = z.object({
  equals: InputJsonValueSchema.optional(),
  path: z.string().array().optional(),
  string_contains: z.string().optional(),
  string_starts_with: z.string().optional(),
  string_ends_with: z.string().optional(),
  array_starts_with: InputJsonValueSchema.optional().nullable(),
  array_ends_with: InputJsonValueSchema.optional().nullable(),
  array_contains: InputJsonValueSchema.optional().nullable(),
  lt: InputJsonValueSchema.optional(),
  lte: InputJsonValueSchema.optional(),
  gt: InputJsonValueSchema.optional(),
  gte: InputJsonValueSchema.optional(),
  not: InputJsonValueSchema.optional(),
  _count: z.lazy(() => NestedIntFilterSchema).optional(),
  _min: z.lazy(() => NestedJsonFilterSchema).optional(),
  _max: z.lazy(() => NestedJsonFilterSchema).optional()
}).strict();

export const BlockchainWalletCountOrderByAggregateInputSchema: z.ZodType<Prisma.BlockchainWalletCountOrderByAggregateInput> = z.object({
  id: z.lazy(() => SortOrderSchema).optional(),
  companyId: z.lazy(() => SortOrderSchema).optional(),
  address: z.lazy(() => SortOrderSchema).optional(),
  privateKey: z.lazy(() => SortOrderSchema).optional(),
  createdAt: z.lazy(() => SortOrderSchema).optional(),
  updatedAt: z.lazy(() => SortOrderSchema).optional()
}).strict();

export const BlockchainWalletAvgOrderByAggregateInputSchema: z.ZodType<Prisma.BlockchainWalletAvgOrderByAggregateInput> = z.object({
  companyId: z.lazy(() => SortOrderSchema).optional()
}).strict();

export const BlockchainWalletMaxOrderByAggregateInputSchema: z.ZodType<Prisma.BlockchainWalletMaxOrderByAggregateInput> = z.object({
  id: z.lazy(() => SortOrderSchema).optional(),
  companyId: z.lazy(() => SortOrderSchema).optional(),
  address: z.lazy(() => SortOrderSchema).optional(),
  privateKey: z.lazy(() => SortOrderSchema).optional(),
  createdAt: z.lazy(() => SortOrderSchema).optional(),
  updatedAt: z.lazy(() => SortOrderSchema).optional()
}).strict();

export const BlockchainWalletMinOrderByAggregateInputSchema: z.ZodType<Prisma.BlockchainWalletMinOrderByAggregateInput> = z.object({
  id: z.lazy(() => SortOrderSchema).optional(),
  companyId: z.lazy(() => SortOrderSchema).optional(),
  address: z.lazy(() => SortOrderSchema).optional(),
  privateKey: z.lazy(() => SortOrderSchema).optional(),
  createdAt: z.lazy(() => SortOrderSchema).optional(),
  updatedAt: z.lazy(() => SortOrderSchema).optional()
}).strict();

export const BlockchainWalletSumOrderByAggregateInputSchema: z.ZodType<Prisma.BlockchainWalletSumOrderByAggregateInput> = z.object({
  companyId: z.lazy(() => SortOrderSchema).optional()
}).strict();

export const ApiKeyCountOrderByAggregateInputSchema: z.ZodType<Prisma.ApiKeyCountOrderByAggregateInput> = z.object({
  id: z.lazy(() => SortOrderSchema).optional(),
  companyId: z.lazy(() => SortOrderSchema).optional(),
  key: z.lazy(() => SortOrderSchema).optional(),
  createdAt: z.lazy(() => SortOrderSchema).optional(),
  updatedAt: z.lazy(() => SortOrderSchema).optional(),
  isActive: z.lazy(() => SortOrderSchema).optional(),
  isDeleted: z.lazy(() => SortOrderSchema).optional(),
  isRevoked: z.lazy(() => SortOrderSchema).optional(),
  lastUsed: z.lazy(() => SortOrderSchema).optional()
}).strict();

export const ApiKeyAvgOrderByAggregateInputSchema: z.ZodType<Prisma.ApiKeyAvgOrderByAggregateInput> = z.object({
  companyId: z.lazy(() => SortOrderSchema).optional()
}).strict();

export const ApiKeyMaxOrderByAggregateInputSchema: z.ZodType<Prisma.ApiKeyMaxOrderByAggregateInput> = z.object({
  id: z.lazy(() => SortOrderSchema).optional(),
  companyId: z.lazy(() => SortOrderSchema).optional(),
  key: z.lazy(() => SortOrderSchema).optional(),
  createdAt: z.lazy(() => SortOrderSchema).optional(),
  updatedAt: z.lazy(() => SortOrderSchema).optional(),
  isActive: z.lazy(() => SortOrderSchema).optional(),
  isDeleted: z.lazy(() => SortOrderSchema).optional(),
  isRevoked: z.lazy(() => SortOrderSchema).optional(),
  lastUsed: z.lazy(() => SortOrderSchema).optional()
}).strict();

export const ApiKeyMinOrderByAggregateInputSchema: z.ZodType<Prisma.ApiKeyMinOrderByAggregateInput> = z.object({
  id: z.lazy(() => SortOrderSchema).optional(),
  companyId: z.lazy(() => SortOrderSchema).optional(),
  key: z.lazy(() => SortOrderSchema).optional(),
  createdAt: z.lazy(() => SortOrderSchema).optional(),
  updatedAt: z.lazy(() => SortOrderSchema).optional(),
  isActive: z.lazy(() => SortOrderSchema).optional(),
  isDeleted: z.lazy(() => SortOrderSchema).optional(),
  isRevoked: z.lazy(() => SortOrderSchema).optional(),
  lastUsed: z.lazy(() => SortOrderSchema).optional()
}).strict();

export const ApiKeySumOrderByAggregateInputSchema: z.ZodType<Prisma.ApiKeySumOrderByAggregateInput> = z.object({
  companyId: z.lazy(() => SortOrderSchema).optional()
}).strict();

export const AuditLogCountOrderByAggregateInputSchema: z.ZodType<Prisma.AuditLogCountOrderByAggregateInput> = z.object({
  id: z.lazy(() => SortOrderSchema).optional(),
  documentId: z.lazy(() => SortOrderSchema).optional(),
  action: z.lazy(() => SortOrderSchema).optional(),
  userId: z.lazy(() => SortOrderSchema).optional(),
  metadata: z.lazy(() => SortOrderSchema).optional(),
  createdAt: z.lazy(() => SortOrderSchema).optional()
}).strict();

export const AuditLogMaxOrderByAggregateInputSchema: z.ZodType<Prisma.AuditLogMaxOrderByAggregateInput> = z.object({
  id: z.lazy(() => SortOrderSchema).optional(),
  documentId: z.lazy(() => SortOrderSchema).optional(),
  action: z.lazy(() => SortOrderSchema).optional(),
  userId: z.lazy(() => SortOrderSchema).optional(),
  createdAt: z.lazy(() => SortOrderSchema).optional()
}).strict();

export const AuditLogMinOrderByAggregateInputSchema: z.ZodType<Prisma.AuditLogMinOrderByAggregateInput> = z.object({
  id: z.lazy(() => SortOrderSchema).optional(),
  documentId: z.lazy(() => SortOrderSchema).optional(),
  action: z.lazy(() => SortOrderSchema).optional(),
  userId: z.lazy(() => SortOrderSchema).optional(),
  createdAt: z.lazy(() => SortOrderSchema).optional()
}).strict();

export const CompanyCreateNestedOneWithoutUsersInputSchema: z.ZodType<Prisma.CompanyCreateNestedOneWithoutUsersInput> = z.object({
  create: z.union([ z.lazy(() => CompanyCreateWithoutUsersInputSchema),z.lazy(() => CompanyUncheckedCreateWithoutUsersInputSchema) ]).optional(),
  connectOrCreate: z.lazy(() => CompanyCreateOrConnectWithoutUsersInputSchema).optional(),
  connect: z.lazy(() => CompanyWhereUniqueInputSchema).optional()
}).strict();

export const DocumentCreateNestedManyWithoutUserInputSchema: z.ZodType<Prisma.DocumentCreateNestedManyWithoutUserInput> = z.object({
  create: z.union([ z.lazy(() => DocumentCreateWithoutUserInputSchema),z.lazy(() => DocumentCreateWithoutUserInputSchema).array(),z.lazy(() => DocumentUncheckedCreateWithoutUserInputSchema),z.lazy(() => DocumentUncheckedCreateWithoutUserInputSchema).array() ]).optional(),
  connectOrCreate: z.union([ z.lazy(() => DocumentCreateOrConnectWithoutUserInputSchema),z.lazy(() => DocumentCreateOrConnectWithoutUserInputSchema).array() ]).optional(),
  createMany: z.lazy(() => DocumentCreateManyUserInputEnvelopeSchema).optional(),
  connect: z.union([ z.lazy(() => DocumentWhereUniqueInputSchema),z.lazy(() => DocumentWhereUniqueInputSchema).array() ]).optional(),
}).strict();

export const SignatureCreateNestedManyWithoutUserInputSchema: z.ZodType<Prisma.SignatureCreateNestedManyWithoutUserInput> = z.object({
  create: z.union([ z.lazy(() => SignatureCreateWithoutUserInputSchema),z.lazy(() => SignatureCreateWithoutUserInputSchema).array(),z.lazy(() => SignatureUncheckedCreateWithoutUserInputSchema),z.lazy(() => SignatureUncheckedCreateWithoutUserInputSchema).array() ]).optional(),
  connectOrCreate: z.union([ z.lazy(() => SignatureCreateOrConnectWithoutUserInputSchema),z.lazy(() => SignatureCreateOrConnectWithoutUserInputSchema).array() ]).optional(),
  createMany: z.lazy(() => SignatureCreateManyUserInputEnvelopeSchema).optional(),
  connect: z.union([ z.lazy(() => SignatureWhereUniqueInputSchema),z.lazy(() => SignatureWhereUniqueInputSchema).array() ]).optional(),
}).strict();

export const ApiKeyCreateNestedManyWithoutUserInputSchema: z.ZodType<Prisma.ApiKeyCreateNestedManyWithoutUserInput> = z.object({
  create: z.union([ z.lazy(() => ApiKeyCreateWithoutUserInputSchema),z.lazy(() => ApiKeyCreateWithoutUserInputSchema).array(),z.lazy(() => ApiKeyUncheckedCreateWithoutUserInputSchema),z.lazy(() => ApiKeyUncheckedCreateWithoutUserInputSchema).array() ]).optional(),
  connectOrCreate: z.union([ z.lazy(() => ApiKeyCreateOrConnectWithoutUserInputSchema),z.lazy(() => ApiKeyCreateOrConnectWithoutUserInputSchema).array() ]).optional(),
  connect: z.union([ z.lazy(() => ApiKeyWhereUniqueInputSchema),z.lazy(() => ApiKeyWhereUniqueInputSchema).array() ]).optional(),
}).strict();

export const DocumentUncheckedCreateNestedManyWithoutUserInputSchema: z.ZodType<Prisma.DocumentUncheckedCreateNestedManyWithoutUserInput> = z.object({
  create: z.union([ z.lazy(() => DocumentCreateWithoutUserInputSchema),z.lazy(() => DocumentCreateWithoutUserInputSchema).array(),z.lazy(() => DocumentUncheckedCreateWithoutUserInputSchema),z.lazy(() => DocumentUncheckedCreateWithoutUserInputSchema).array() ]).optional(),
  connectOrCreate: z.union([ z.lazy(() => DocumentCreateOrConnectWithoutUserInputSchema),z.lazy(() => DocumentCreateOrConnectWithoutUserInputSchema).array() ]).optional(),
  createMany: z.lazy(() => DocumentCreateManyUserInputEnvelopeSchema).optional(),
  connect: z.union([ z.lazy(() => DocumentWhereUniqueInputSchema),z.lazy(() => DocumentWhereUniqueInputSchema).array() ]).optional(),
}).strict();

export const SignatureUncheckedCreateNestedManyWithoutUserInputSchema: z.ZodType<Prisma.SignatureUncheckedCreateNestedManyWithoutUserInput> = z.object({
  create: z.union([ z.lazy(() => SignatureCreateWithoutUserInputSchema),z.lazy(() => SignatureCreateWithoutUserInputSchema).array(),z.lazy(() => SignatureUncheckedCreateWithoutUserInputSchema),z.lazy(() => SignatureUncheckedCreateWithoutUserInputSchema).array() ]).optional(),
  connectOrCreate: z.union([ z.lazy(() => SignatureCreateOrConnectWithoutUserInputSchema),z.lazy(() => SignatureCreateOrConnectWithoutUserInputSchema).array() ]).optional(),
  createMany: z.lazy(() => SignatureCreateManyUserInputEnvelopeSchema).optional(),
  connect: z.union([ z.lazy(() => SignatureWhereUniqueInputSchema),z.lazy(() => SignatureWhereUniqueInputSchema).array() ]).optional(),
}).strict();

export const ApiKeyUncheckedCreateNestedManyWithoutUserInputSchema: z.ZodType<Prisma.ApiKeyUncheckedCreateNestedManyWithoutUserInput> = z.object({
  create: z.union([ z.lazy(() => ApiKeyCreateWithoutUserInputSchema),z.lazy(() => ApiKeyCreateWithoutUserInputSchema).array(),z.lazy(() => ApiKeyUncheckedCreateWithoutUserInputSchema),z.lazy(() => ApiKeyUncheckedCreateWithoutUserInputSchema).array() ]).optional(),
  connectOrCreate: z.union([ z.lazy(() => ApiKeyCreateOrConnectWithoutUserInputSchema),z.lazy(() => ApiKeyCreateOrConnectWithoutUserInputSchema).array() ]).optional(),
  connect: z.union([ z.lazy(() => ApiKeyWhereUniqueInputSchema),z.lazy(() => ApiKeyWhereUniqueInputSchema).array() ]).optional(),
}).strict();

export const StringFieldUpdateOperationsInputSchema: z.ZodType<Prisma.StringFieldUpdateOperationsInput> = z.object({
  set: z.string().optional()
}).strict();

export const EnumUserRoleFieldUpdateOperationsInputSchema: z.ZodType<Prisma.EnumUserRoleFieldUpdateOperationsInput> = z.object({
  set: z.lazy(() => UserRoleSchema).optional()
}).strict();

export const DateTimeFieldUpdateOperationsInputSchema: z.ZodType<Prisma.DateTimeFieldUpdateOperationsInput> = z.object({
  set: z.coerce.date().optional()
}).strict();

export const CompanyUpdateOneRequiredWithoutUsersNestedInputSchema: z.ZodType<Prisma.CompanyUpdateOneRequiredWithoutUsersNestedInput> = z.object({
  create: z.union([ z.lazy(() => CompanyCreateWithoutUsersInputSchema),z.lazy(() => CompanyUncheckedCreateWithoutUsersInputSchema) ]).optional(),
  connectOrCreate: z.lazy(() => CompanyCreateOrConnectWithoutUsersInputSchema).optional(),
  upsert: z.lazy(() => CompanyUpsertWithoutUsersInputSchema).optional(),
  connect: z.lazy(() => CompanyWhereUniqueInputSchema).optional(),
  update: z.union([ z.lazy(() => CompanyUpdateToOneWithWhereWithoutUsersInputSchema),z.lazy(() => CompanyUpdateWithoutUsersInputSchema),z.lazy(() => CompanyUncheckedUpdateWithoutUsersInputSchema) ]).optional(),
}).strict();

export const DocumentUpdateManyWithoutUserNestedInputSchema: z.ZodType<Prisma.DocumentUpdateManyWithoutUserNestedInput> = z.object({
  create: z.union([ z.lazy(() => DocumentCreateWithoutUserInputSchema),z.lazy(() => DocumentCreateWithoutUserInputSchema).array(),z.lazy(() => DocumentUncheckedCreateWithoutUserInputSchema),z.lazy(() => DocumentUncheckedCreateWithoutUserInputSchema).array() ]).optional(),
  connectOrCreate: z.union([ z.lazy(() => DocumentCreateOrConnectWithoutUserInputSchema),z.lazy(() => DocumentCreateOrConnectWithoutUserInputSchema).array() ]).optional(),
  upsert: z.union([ z.lazy(() => DocumentUpsertWithWhereUniqueWithoutUserInputSchema),z.lazy(() => DocumentUpsertWithWhereUniqueWithoutUserInputSchema).array() ]).optional(),
  createMany: z.lazy(() => DocumentCreateManyUserInputEnvelopeSchema).optional(),
  set: z.union([ z.lazy(() => DocumentWhereUniqueInputSchema),z.lazy(() => DocumentWhereUniqueInputSchema).array() ]).optional(),
  disconnect: z.union([ z.lazy(() => DocumentWhereUniqueInputSchema),z.lazy(() => DocumentWhereUniqueInputSchema).array() ]).optional(),
  delete: z.union([ z.lazy(() => DocumentWhereUniqueInputSchema),z.lazy(() => DocumentWhereUniqueInputSchema).array() ]).optional(),
  connect: z.union([ z.lazy(() => DocumentWhereUniqueInputSchema),z.lazy(() => DocumentWhereUniqueInputSchema).array() ]).optional(),
  update: z.union([ z.lazy(() => DocumentUpdateWithWhereUniqueWithoutUserInputSchema),z.lazy(() => DocumentUpdateWithWhereUniqueWithoutUserInputSchema).array() ]).optional(),
  updateMany: z.union([ z.lazy(() => DocumentUpdateManyWithWhereWithoutUserInputSchema),z.lazy(() => DocumentUpdateManyWithWhereWithoutUserInputSchema).array() ]).optional(),
  deleteMany: z.union([ z.lazy(() => DocumentScalarWhereInputSchema),z.lazy(() => DocumentScalarWhereInputSchema).array() ]).optional(),
}).strict();

export const SignatureUpdateManyWithoutUserNestedInputSchema: z.ZodType<Prisma.SignatureUpdateManyWithoutUserNestedInput> = z.object({
  create: z.union([ z.lazy(() => SignatureCreateWithoutUserInputSchema),z.lazy(() => SignatureCreateWithoutUserInputSchema).array(),z.lazy(() => SignatureUncheckedCreateWithoutUserInputSchema),z.lazy(() => SignatureUncheckedCreateWithoutUserInputSchema).array() ]).optional(),
  connectOrCreate: z.union([ z.lazy(() => SignatureCreateOrConnectWithoutUserInputSchema),z.lazy(() => SignatureCreateOrConnectWithoutUserInputSchema).array() ]).optional(),
  upsert: z.union([ z.lazy(() => SignatureUpsertWithWhereUniqueWithoutUserInputSchema),z.lazy(() => SignatureUpsertWithWhereUniqueWithoutUserInputSchema).array() ]).optional(),
  createMany: z.lazy(() => SignatureCreateManyUserInputEnvelopeSchema).optional(),
  set: z.union([ z.lazy(() => SignatureWhereUniqueInputSchema),z.lazy(() => SignatureWhereUniqueInputSchema).array() ]).optional(),
  disconnect: z.union([ z.lazy(() => SignatureWhereUniqueInputSchema),z.lazy(() => SignatureWhereUniqueInputSchema).array() ]).optional(),
  delete: z.union([ z.lazy(() => SignatureWhereUniqueInputSchema),z.lazy(() => SignatureWhereUniqueInputSchema).array() ]).optional(),
  connect: z.union([ z.lazy(() => SignatureWhereUniqueInputSchema),z.lazy(() => SignatureWhereUniqueInputSchema).array() ]).optional(),
  update: z.union([ z.lazy(() => SignatureUpdateWithWhereUniqueWithoutUserInputSchema),z.lazy(() => SignatureUpdateWithWhereUniqueWithoutUserInputSchema).array() ]).optional(),
  updateMany: z.union([ z.lazy(() => SignatureUpdateManyWithWhereWithoutUserInputSchema),z.lazy(() => SignatureUpdateManyWithWhereWithoutUserInputSchema).array() ]).optional(),
  deleteMany: z.union([ z.lazy(() => SignatureScalarWhereInputSchema),z.lazy(() => SignatureScalarWhereInputSchema).array() ]).optional(),
}).strict();

export const ApiKeyUpdateManyWithoutUserNestedInputSchema: z.ZodType<Prisma.ApiKeyUpdateManyWithoutUserNestedInput> = z.object({
  create: z.union([ z.lazy(() => ApiKeyCreateWithoutUserInputSchema),z.lazy(() => ApiKeyCreateWithoutUserInputSchema).array(),z.lazy(() => ApiKeyUncheckedCreateWithoutUserInputSchema),z.lazy(() => ApiKeyUncheckedCreateWithoutUserInputSchema).array() ]).optional(),
  connectOrCreate: z.union([ z.lazy(() => ApiKeyCreateOrConnectWithoutUserInputSchema),z.lazy(() => ApiKeyCreateOrConnectWithoutUserInputSchema).array() ]).optional(),
  upsert: z.union([ z.lazy(() => ApiKeyUpsertWithWhereUniqueWithoutUserInputSchema),z.lazy(() => ApiKeyUpsertWithWhereUniqueWithoutUserInputSchema).array() ]).optional(),
  set: z.union([ z.lazy(() => ApiKeyWhereUniqueInputSchema),z.lazy(() => ApiKeyWhereUniqueInputSchema).array() ]).optional(),
  disconnect: z.union([ z.lazy(() => ApiKeyWhereUniqueInputSchema),z.lazy(() => ApiKeyWhereUniqueInputSchema).array() ]).optional(),
  delete: z.union([ z.lazy(() => ApiKeyWhereUniqueInputSchema),z.lazy(() => ApiKeyWhereUniqueInputSchema).array() ]).optional(),
  connect: z.union([ z.lazy(() => ApiKeyWhereUniqueInputSchema),z.lazy(() => ApiKeyWhereUniqueInputSchema).array() ]).optional(),
  update: z.union([ z.lazy(() => ApiKeyUpdateWithWhereUniqueWithoutUserInputSchema),z.lazy(() => ApiKeyUpdateWithWhereUniqueWithoutUserInputSchema).array() ]).optional(),
  updateMany: z.union([ z.lazy(() => ApiKeyUpdateManyWithWhereWithoutUserInputSchema),z.lazy(() => ApiKeyUpdateManyWithWhereWithoutUserInputSchema).array() ]).optional(),
  deleteMany: z.union([ z.lazy(() => ApiKeyScalarWhereInputSchema),z.lazy(() => ApiKeyScalarWhereInputSchema).array() ]).optional(),
}).strict();

export const IntFieldUpdateOperationsInputSchema: z.ZodType<Prisma.IntFieldUpdateOperationsInput> = z.object({
  set: z.number().optional(),
  increment: z.number().optional(),
  decrement: z.number().optional(),
  multiply: z.number().optional(),
  divide: z.number().optional()
}).strict();

export const DocumentUncheckedUpdateManyWithoutUserNestedInputSchema: z.ZodType<Prisma.DocumentUncheckedUpdateManyWithoutUserNestedInput> = z.object({
  create: z.union([ z.lazy(() => DocumentCreateWithoutUserInputSchema),z.lazy(() => DocumentCreateWithoutUserInputSchema).array(),z.lazy(() => DocumentUncheckedCreateWithoutUserInputSchema),z.lazy(() => DocumentUncheckedCreateWithoutUserInputSchema).array() ]).optional(),
  connectOrCreate: z.union([ z.lazy(() => DocumentCreateOrConnectWithoutUserInputSchema),z.lazy(() => DocumentCreateOrConnectWithoutUserInputSchema).array() ]).optional(),
  upsert: z.union([ z.lazy(() => DocumentUpsertWithWhereUniqueWithoutUserInputSchema),z.lazy(() => DocumentUpsertWithWhereUniqueWithoutUserInputSchema).array() ]).optional(),
  createMany: z.lazy(() => DocumentCreateManyUserInputEnvelopeSchema).optional(),
  set: z.union([ z.lazy(() => DocumentWhereUniqueInputSchema),z.lazy(() => DocumentWhereUniqueInputSchema).array() ]).optional(),
  disconnect: z.union([ z.lazy(() => DocumentWhereUniqueInputSchema),z.lazy(() => DocumentWhereUniqueInputSchema).array() ]).optional(),
  delete: z.union([ z.lazy(() => DocumentWhereUniqueInputSchema),z.lazy(() => DocumentWhereUniqueInputSchema).array() ]).optional(),
  connect: z.union([ z.lazy(() => DocumentWhereUniqueInputSchema),z.lazy(() => DocumentWhereUniqueInputSchema).array() ]).optional(),
  update: z.union([ z.lazy(() => DocumentUpdateWithWhereUniqueWithoutUserInputSchema),z.lazy(() => DocumentUpdateWithWhereUniqueWithoutUserInputSchema).array() ]).optional(),
  updateMany: z.union([ z.lazy(() => DocumentUpdateManyWithWhereWithoutUserInputSchema),z.lazy(() => DocumentUpdateManyWithWhereWithoutUserInputSchema).array() ]).optional(),
  deleteMany: z.union([ z.lazy(() => DocumentScalarWhereInputSchema),z.lazy(() => DocumentScalarWhereInputSchema).array() ]).optional(),
}).strict();

export const SignatureUncheckedUpdateManyWithoutUserNestedInputSchema: z.ZodType<Prisma.SignatureUncheckedUpdateManyWithoutUserNestedInput> = z.object({
  create: z.union([ z.lazy(() => SignatureCreateWithoutUserInputSchema),z.lazy(() => SignatureCreateWithoutUserInputSchema).array(),z.lazy(() => SignatureUncheckedCreateWithoutUserInputSchema),z.lazy(() => SignatureUncheckedCreateWithoutUserInputSchema).array() ]).optional(),
  connectOrCreate: z.union([ z.lazy(() => SignatureCreateOrConnectWithoutUserInputSchema),z.lazy(() => SignatureCreateOrConnectWithoutUserInputSchema).array() ]).optional(),
  upsert: z.union([ z.lazy(() => SignatureUpsertWithWhereUniqueWithoutUserInputSchema),z.lazy(() => SignatureUpsertWithWhereUniqueWithoutUserInputSchema).array() ]).optional(),
  createMany: z.lazy(() => SignatureCreateManyUserInputEnvelopeSchema).optional(),
  set: z.union([ z.lazy(() => SignatureWhereUniqueInputSchema),z.lazy(() => SignatureWhereUniqueInputSchema).array() ]).optional(),
  disconnect: z.union([ z.lazy(() => SignatureWhereUniqueInputSchema),z.lazy(() => SignatureWhereUniqueInputSchema).array() ]).optional(),
  delete: z.union([ z.lazy(() => SignatureWhereUniqueInputSchema),z.lazy(() => SignatureWhereUniqueInputSchema).array() ]).optional(),
  connect: z.union([ z.lazy(() => SignatureWhereUniqueInputSchema),z.lazy(() => SignatureWhereUniqueInputSchema).array() ]).optional(),
  update: z.union([ z.lazy(() => SignatureUpdateWithWhereUniqueWithoutUserInputSchema),z.lazy(() => SignatureUpdateWithWhereUniqueWithoutUserInputSchema).array() ]).optional(),
  updateMany: z.union([ z.lazy(() => SignatureUpdateManyWithWhereWithoutUserInputSchema),z.lazy(() => SignatureUpdateManyWithWhereWithoutUserInputSchema).array() ]).optional(),
  deleteMany: z.union([ z.lazy(() => SignatureScalarWhereInputSchema),z.lazy(() => SignatureScalarWhereInputSchema).array() ]).optional(),
}).strict();

export const ApiKeyUncheckedUpdateManyWithoutUserNestedInputSchema: z.ZodType<Prisma.ApiKeyUncheckedUpdateManyWithoutUserNestedInput> = z.object({
  create: z.union([ z.lazy(() => ApiKeyCreateWithoutUserInputSchema),z.lazy(() => ApiKeyCreateWithoutUserInputSchema).array(),z.lazy(() => ApiKeyUncheckedCreateWithoutUserInputSchema),z.lazy(() => ApiKeyUncheckedCreateWithoutUserInputSchema).array() ]).optional(),
  connectOrCreate: z.union([ z.lazy(() => ApiKeyCreateOrConnectWithoutUserInputSchema),z.lazy(() => ApiKeyCreateOrConnectWithoutUserInputSchema).array() ]).optional(),
  upsert: z.union([ z.lazy(() => ApiKeyUpsertWithWhereUniqueWithoutUserInputSchema),z.lazy(() => ApiKeyUpsertWithWhereUniqueWithoutUserInputSchema).array() ]).optional(),
  set: z.union([ z.lazy(() => ApiKeyWhereUniqueInputSchema),z.lazy(() => ApiKeyWhereUniqueInputSchema).array() ]).optional(),
  disconnect: z.union([ z.lazy(() => ApiKeyWhereUniqueInputSchema),z.lazy(() => ApiKeyWhereUniqueInputSchema).array() ]).optional(),
  delete: z.union([ z.lazy(() => ApiKeyWhereUniqueInputSchema),z.lazy(() => ApiKeyWhereUniqueInputSchema).array() ]).optional(),
  connect: z.union([ z.lazy(() => ApiKeyWhereUniqueInputSchema),z.lazy(() => ApiKeyWhereUniqueInputSchema).array() ]).optional(),
  update: z.union([ z.lazy(() => ApiKeyUpdateWithWhereUniqueWithoutUserInputSchema),z.lazy(() => ApiKeyUpdateWithWhereUniqueWithoutUserInputSchema).array() ]).optional(),
  updateMany: z.union([ z.lazy(() => ApiKeyUpdateManyWithWhereWithoutUserInputSchema),z.lazy(() => ApiKeyUpdateManyWithWhereWithoutUserInputSchema).array() ]).optional(),
  deleteMany: z.union([ z.lazy(() => ApiKeyScalarWhereInputSchema),z.lazy(() => ApiKeyScalarWhereInputSchema).array() ]).optional(),
}).strict();

export const UserCreateNestedManyWithoutCompanyInputSchema: z.ZodType<Prisma.UserCreateNestedManyWithoutCompanyInput> = z.object({
  create: z.union([ z.lazy(() => UserCreateWithoutCompanyInputSchema),z.lazy(() => UserCreateWithoutCompanyInputSchema).array(),z.lazy(() => UserUncheckedCreateWithoutCompanyInputSchema),z.lazy(() => UserUncheckedCreateWithoutCompanyInputSchema).array() ]).optional(),
  connectOrCreate: z.union([ z.lazy(() => UserCreateOrConnectWithoutCompanyInputSchema),z.lazy(() => UserCreateOrConnectWithoutCompanyInputSchema).array() ]).optional(),
  createMany: z.lazy(() => UserCreateManyCompanyInputEnvelopeSchema).optional(),
  connect: z.union([ z.lazy(() => UserWhereUniqueInputSchema),z.lazy(() => UserWhereUniqueInputSchema).array() ]).optional(),
}).strict();

export const DocumentCreateNestedManyWithoutCompanyInputSchema: z.ZodType<Prisma.DocumentCreateNestedManyWithoutCompanyInput> = z.object({
  create: z.union([ z.lazy(() => DocumentCreateWithoutCompanyInputSchema),z.lazy(() => DocumentCreateWithoutCompanyInputSchema).array(),z.lazy(() => DocumentUncheckedCreateWithoutCompanyInputSchema),z.lazy(() => DocumentUncheckedCreateWithoutCompanyInputSchema).array() ]).optional(),
  connectOrCreate: z.union([ z.lazy(() => DocumentCreateOrConnectWithoutCompanyInputSchema),z.lazy(() => DocumentCreateOrConnectWithoutCompanyInputSchema).array() ]).optional(),
  createMany: z.lazy(() => DocumentCreateManyCompanyInputEnvelopeSchema).optional(),
  connect: z.union([ z.lazy(() => DocumentWhereUniqueInputSchema),z.lazy(() => DocumentWhereUniqueInputSchema).array() ]).optional(),
}).strict();

export const CertificateCreateNestedManyWithoutCompanyInputSchema: z.ZodType<Prisma.CertificateCreateNestedManyWithoutCompanyInput> = z.object({
  create: z.union([ z.lazy(() => CertificateCreateWithoutCompanyInputSchema),z.lazy(() => CertificateCreateWithoutCompanyInputSchema).array(),z.lazy(() => CertificateUncheckedCreateWithoutCompanyInputSchema),z.lazy(() => CertificateUncheckedCreateWithoutCompanyInputSchema).array() ]).optional(),
  connectOrCreate: z.union([ z.lazy(() => CertificateCreateOrConnectWithoutCompanyInputSchema),z.lazy(() => CertificateCreateOrConnectWithoutCompanyInputSchema).array() ]).optional(),
  createMany: z.lazy(() => CertificateCreateManyCompanyInputEnvelopeSchema).optional(),
  connect: z.union([ z.lazy(() => CertificateWhereUniqueInputSchema),z.lazy(() => CertificateWhereUniqueInputSchema).array() ]).optional(),
}).strict();

export const BlockchainWalletCreateNestedOneWithoutCompanyInputSchema: z.ZodType<Prisma.BlockchainWalletCreateNestedOneWithoutCompanyInput> = z.object({
  create: z.union([ z.lazy(() => BlockchainWalletCreateWithoutCompanyInputSchema),z.lazy(() => BlockchainWalletUncheckedCreateWithoutCompanyInputSchema) ]).optional(),
  connectOrCreate: z.lazy(() => BlockchainWalletCreateOrConnectWithoutCompanyInputSchema).optional(),
  connect: z.lazy(() => BlockchainWalletWhereUniqueInputSchema).optional()
}).strict();

export const SigningTemplateCreateNestedManyWithoutCompanyInputSchema: z.ZodType<Prisma.SigningTemplateCreateNestedManyWithoutCompanyInput> = z.object({
  create: z.union([ z.lazy(() => SigningTemplateCreateWithoutCompanyInputSchema),z.lazy(() => SigningTemplateCreateWithoutCompanyInputSchema).array(),z.lazy(() => SigningTemplateUncheckedCreateWithoutCompanyInputSchema),z.lazy(() => SigningTemplateUncheckedCreateWithoutCompanyInputSchema).array() ]).optional(),
  connectOrCreate: z.union([ z.lazy(() => SigningTemplateCreateOrConnectWithoutCompanyInputSchema),z.lazy(() => SigningTemplateCreateOrConnectWithoutCompanyInputSchema).array() ]).optional(),
  createMany: z.lazy(() => SigningTemplateCreateManyCompanyInputEnvelopeSchema).optional(),
  connect: z.union([ z.lazy(() => SigningTemplateWhereUniqueInputSchema),z.lazy(() => SigningTemplateWhereUniqueInputSchema).array() ]).optional(),
}).strict();

export const ApiKeyCreateNestedManyWithoutCompanyInputSchema: z.ZodType<Prisma.ApiKeyCreateNestedManyWithoutCompanyInput> = z.object({
  create: z.union([ z.lazy(() => ApiKeyCreateWithoutCompanyInputSchema),z.lazy(() => ApiKeyCreateWithoutCompanyInputSchema).array(),z.lazy(() => ApiKeyUncheckedCreateWithoutCompanyInputSchema),z.lazy(() => ApiKeyUncheckedCreateWithoutCompanyInputSchema).array() ]).optional(),
  connectOrCreate: z.union([ z.lazy(() => ApiKeyCreateOrConnectWithoutCompanyInputSchema),z.lazy(() => ApiKeyCreateOrConnectWithoutCompanyInputSchema).array() ]).optional(),
  createMany: z.lazy(() => ApiKeyCreateManyCompanyInputEnvelopeSchema).optional(),
  connect: z.union([ z.lazy(() => ApiKeyWhereUniqueInputSchema),z.lazy(() => ApiKeyWhereUniqueInputSchema).array() ]).optional(),
}).strict();

export const UserUncheckedCreateNestedManyWithoutCompanyInputSchema: z.ZodType<Prisma.UserUncheckedCreateNestedManyWithoutCompanyInput> = z.object({
  create: z.union([ z.lazy(() => UserCreateWithoutCompanyInputSchema),z.lazy(() => UserCreateWithoutCompanyInputSchema).array(),z.lazy(() => UserUncheckedCreateWithoutCompanyInputSchema),z.lazy(() => UserUncheckedCreateWithoutCompanyInputSchema).array() ]).optional(),
  connectOrCreate: z.union([ z.lazy(() => UserCreateOrConnectWithoutCompanyInputSchema),z.lazy(() => UserCreateOrConnectWithoutCompanyInputSchema).array() ]).optional(),
  createMany: z.lazy(() => UserCreateManyCompanyInputEnvelopeSchema).optional(),
  connect: z.union([ z.lazy(() => UserWhereUniqueInputSchema),z.lazy(() => UserWhereUniqueInputSchema).array() ]).optional(),
}).strict();

export const DocumentUncheckedCreateNestedManyWithoutCompanyInputSchema: z.ZodType<Prisma.DocumentUncheckedCreateNestedManyWithoutCompanyInput> = z.object({
  create: z.union([ z.lazy(() => DocumentCreateWithoutCompanyInputSchema),z.lazy(() => DocumentCreateWithoutCompanyInputSchema).array(),z.lazy(() => DocumentUncheckedCreateWithoutCompanyInputSchema),z.lazy(() => DocumentUncheckedCreateWithoutCompanyInputSchema).array() ]).optional(),
  connectOrCreate: z.union([ z.lazy(() => DocumentCreateOrConnectWithoutCompanyInputSchema),z.lazy(() => DocumentCreateOrConnectWithoutCompanyInputSchema).array() ]).optional(),
  createMany: z.lazy(() => DocumentCreateManyCompanyInputEnvelopeSchema).optional(),
  connect: z.union([ z.lazy(() => DocumentWhereUniqueInputSchema),z.lazy(() => DocumentWhereUniqueInputSchema).array() ]).optional(),
}).strict();

export const CertificateUncheckedCreateNestedManyWithoutCompanyInputSchema: z.ZodType<Prisma.CertificateUncheckedCreateNestedManyWithoutCompanyInput> = z.object({
  create: z.union([ z.lazy(() => CertificateCreateWithoutCompanyInputSchema),z.lazy(() => CertificateCreateWithoutCompanyInputSchema).array(),z.lazy(() => CertificateUncheckedCreateWithoutCompanyInputSchema),z.lazy(() => CertificateUncheckedCreateWithoutCompanyInputSchema).array() ]).optional(),
  connectOrCreate: z.union([ z.lazy(() => CertificateCreateOrConnectWithoutCompanyInputSchema),z.lazy(() => CertificateCreateOrConnectWithoutCompanyInputSchema).array() ]).optional(),
  createMany: z.lazy(() => CertificateCreateManyCompanyInputEnvelopeSchema).optional(),
  connect: z.union([ z.lazy(() => CertificateWhereUniqueInputSchema),z.lazy(() => CertificateWhereUniqueInputSchema).array() ]).optional(),
}).strict();

export const BlockchainWalletUncheckedCreateNestedOneWithoutCompanyInputSchema: z.ZodType<Prisma.BlockchainWalletUncheckedCreateNestedOneWithoutCompanyInput> = z.object({
  create: z.union([ z.lazy(() => BlockchainWalletCreateWithoutCompanyInputSchema),z.lazy(() => BlockchainWalletUncheckedCreateWithoutCompanyInputSchema) ]).optional(),
  connectOrCreate: z.lazy(() => BlockchainWalletCreateOrConnectWithoutCompanyInputSchema).optional(),
  connect: z.lazy(() => BlockchainWalletWhereUniqueInputSchema).optional()
}).strict();

export const SigningTemplateUncheckedCreateNestedManyWithoutCompanyInputSchema: z.ZodType<Prisma.SigningTemplateUncheckedCreateNestedManyWithoutCompanyInput> = z.object({
  create: z.union([ z.lazy(() => SigningTemplateCreateWithoutCompanyInputSchema),z.lazy(() => SigningTemplateCreateWithoutCompanyInputSchema).array(),z.lazy(() => SigningTemplateUncheckedCreateWithoutCompanyInputSchema),z.lazy(() => SigningTemplateUncheckedCreateWithoutCompanyInputSchema).array() ]).optional(),
  connectOrCreate: z.union([ z.lazy(() => SigningTemplateCreateOrConnectWithoutCompanyInputSchema),z.lazy(() => SigningTemplateCreateOrConnectWithoutCompanyInputSchema).array() ]).optional(),
  createMany: z.lazy(() => SigningTemplateCreateManyCompanyInputEnvelopeSchema).optional(),
  connect: z.union([ z.lazy(() => SigningTemplateWhereUniqueInputSchema),z.lazy(() => SigningTemplateWhereUniqueInputSchema).array() ]).optional(),
}).strict();

export const ApiKeyUncheckedCreateNestedManyWithoutCompanyInputSchema: z.ZodType<Prisma.ApiKeyUncheckedCreateNestedManyWithoutCompanyInput> = z.object({
  create: z.union([ z.lazy(() => ApiKeyCreateWithoutCompanyInputSchema),z.lazy(() => ApiKeyCreateWithoutCompanyInputSchema).array(),z.lazy(() => ApiKeyUncheckedCreateWithoutCompanyInputSchema),z.lazy(() => ApiKeyUncheckedCreateWithoutCompanyInputSchema).array() ]).optional(),
  connectOrCreate: z.union([ z.lazy(() => ApiKeyCreateOrConnectWithoutCompanyInputSchema),z.lazy(() => ApiKeyCreateOrConnectWithoutCompanyInputSchema).array() ]).optional(),
  createMany: z.lazy(() => ApiKeyCreateManyCompanyInputEnvelopeSchema).optional(),
  connect: z.union([ z.lazy(() => ApiKeyWhereUniqueInputSchema),z.lazy(() => ApiKeyWhereUniqueInputSchema).array() ]).optional(),
}).strict();

export const NullableStringFieldUpdateOperationsInputSchema: z.ZodType<Prisma.NullableStringFieldUpdateOperationsInput> = z.object({
  set: z.string().optional().nullable()
}).strict();

export const UserUpdateManyWithoutCompanyNestedInputSchema: z.ZodType<Prisma.UserUpdateManyWithoutCompanyNestedInput> = z.object({
  create: z.union([ z.lazy(() => UserCreateWithoutCompanyInputSchema),z.lazy(() => UserCreateWithoutCompanyInputSchema).array(),z.lazy(() => UserUncheckedCreateWithoutCompanyInputSchema),z.lazy(() => UserUncheckedCreateWithoutCompanyInputSchema).array() ]).optional(),
  connectOrCreate: z.union([ z.lazy(() => UserCreateOrConnectWithoutCompanyInputSchema),z.lazy(() => UserCreateOrConnectWithoutCompanyInputSchema).array() ]).optional(),
  upsert: z.union([ z.lazy(() => UserUpsertWithWhereUniqueWithoutCompanyInputSchema),z.lazy(() => UserUpsertWithWhereUniqueWithoutCompanyInputSchema).array() ]).optional(),
  createMany: z.lazy(() => UserCreateManyCompanyInputEnvelopeSchema).optional(),
  set: z.union([ z.lazy(() => UserWhereUniqueInputSchema),z.lazy(() => UserWhereUniqueInputSchema).array() ]).optional(),
  disconnect: z.union([ z.lazy(() => UserWhereUniqueInputSchema),z.lazy(() => UserWhereUniqueInputSchema).array() ]).optional(),
  delete: z.union([ z.lazy(() => UserWhereUniqueInputSchema),z.lazy(() => UserWhereUniqueInputSchema).array() ]).optional(),
  connect: z.union([ z.lazy(() => UserWhereUniqueInputSchema),z.lazy(() => UserWhereUniqueInputSchema).array() ]).optional(),
  update: z.union([ z.lazy(() => UserUpdateWithWhereUniqueWithoutCompanyInputSchema),z.lazy(() => UserUpdateWithWhereUniqueWithoutCompanyInputSchema).array() ]).optional(),
  updateMany: z.union([ z.lazy(() => UserUpdateManyWithWhereWithoutCompanyInputSchema),z.lazy(() => UserUpdateManyWithWhereWithoutCompanyInputSchema).array() ]).optional(),
  deleteMany: z.union([ z.lazy(() => UserScalarWhereInputSchema),z.lazy(() => UserScalarWhereInputSchema).array() ]).optional(),
}).strict();

export const DocumentUpdateManyWithoutCompanyNestedInputSchema: z.ZodType<Prisma.DocumentUpdateManyWithoutCompanyNestedInput> = z.object({
  create: z.union([ z.lazy(() => DocumentCreateWithoutCompanyInputSchema),z.lazy(() => DocumentCreateWithoutCompanyInputSchema).array(),z.lazy(() => DocumentUncheckedCreateWithoutCompanyInputSchema),z.lazy(() => DocumentUncheckedCreateWithoutCompanyInputSchema).array() ]).optional(),
  connectOrCreate: z.union([ z.lazy(() => DocumentCreateOrConnectWithoutCompanyInputSchema),z.lazy(() => DocumentCreateOrConnectWithoutCompanyInputSchema).array() ]).optional(),
  upsert: z.union([ z.lazy(() => DocumentUpsertWithWhereUniqueWithoutCompanyInputSchema),z.lazy(() => DocumentUpsertWithWhereUniqueWithoutCompanyInputSchema).array() ]).optional(),
  createMany: z.lazy(() => DocumentCreateManyCompanyInputEnvelopeSchema).optional(),
  set: z.union([ z.lazy(() => DocumentWhereUniqueInputSchema),z.lazy(() => DocumentWhereUniqueInputSchema).array() ]).optional(),
  disconnect: z.union([ z.lazy(() => DocumentWhereUniqueInputSchema),z.lazy(() => DocumentWhereUniqueInputSchema).array() ]).optional(),
  delete: z.union([ z.lazy(() => DocumentWhereUniqueInputSchema),z.lazy(() => DocumentWhereUniqueInputSchema).array() ]).optional(),
  connect: z.union([ z.lazy(() => DocumentWhereUniqueInputSchema),z.lazy(() => DocumentWhereUniqueInputSchema).array() ]).optional(),
  update: z.union([ z.lazy(() => DocumentUpdateWithWhereUniqueWithoutCompanyInputSchema),z.lazy(() => DocumentUpdateWithWhereUniqueWithoutCompanyInputSchema).array() ]).optional(),
  updateMany: z.union([ z.lazy(() => DocumentUpdateManyWithWhereWithoutCompanyInputSchema),z.lazy(() => DocumentUpdateManyWithWhereWithoutCompanyInputSchema).array() ]).optional(),
  deleteMany: z.union([ z.lazy(() => DocumentScalarWhereInputSchema),z.lazy(() => DocumentScalarWhereInputSchema).array() ]).optional(),
}).strict();

export const CertificateUpdateManyWithoutCompanyNestedInputSchema: z.ZodType<Prisma.CertificateUpdateManyWithoutCompanyNestedInput> = z.object({
  create: z.union([ z.lazy(() => CertificateCreateWithoutCompanyInputSchema),z.lazy(() => CertificateCreateWithoutCompanyInputSchema).array(),z.lazy(() => CertificateUncheckedCreateWithoutCompanyInputSchema),z.lazy(() => CertificateUncheckedCreateWithoutCompanyInputSchema).array() ]).optional(),
  connectOrCreate: z.union([ z.lazy(() => CertificateCreateOrConnectWithoutCompanyInputSchema),z.lazy(() => CertificateCreateOrConnectWithoutCompanyInputSchema).array() ]).optional(),
  upsert: z.union([ z.lazy(() => CertificateUpsertWithWhereUniqueWithoutCompanyInputSchema),z.lazy(() => CertificateUpsertWithWhereUniqueWithoutCompanyInputSchema).array() ]).optional(),
  createMany: z.lazy(() => CertificateCreateManyCompanyInputEnvelopeSchema).optional(),
  set: z.union([ z.lazy(() => CertificateWhereUniqueInputSchema),z.lazy(() => CertificateWhereUniqueInputSchema).array() ]).optional(),
  disconnect: z.union([ z.lazy(() => CertificateWhereUniqueInputSchema),z.lazy(() => CertificateWhereUniqueInputSchema).array() ]).optional(),
  delete: z.union([ z.lazy(() => CertificateWhereUniqueInputSchema),z.lazy(() => CertificateWhereUniqueInputSchema).array() ]).optional(),
  connect: z.union([ z.lazy(() => CertificateWhereUniqueInputSchema),z.lazy(() => CertificateWhereUniqueInputSchema).array() ]).optional(),
  update: z.union([ z.lazy(() => CertificateUpdateWithWhereUniqueWithoutCompanyInputSchema),z.lazy(() => CertificateUpdateWithWhereUniqueWithoutCompanyInputSchema).array() ]).optional(),
  updateMany: z.union([ z.lazy(() => CertificateUpdateManyWithWhereWithoutCompanyInputSchema),z.lazy(() => CertificateUpdateManyWithWhereWithoutCompanyInputSchema).array() ]).optional(),
  deleteMany: z.union([ z.lazy(() => CertificateScalarWhereInputSchema),z.lazy(() => CertificateScalarWhereInputSchema).array() ]).optional(),
}).strict();

export const BlockchainWalletUpdateOneWithoutCompanyNestedInputSchema: z.ZodType<Prisma.BlockchainWalletUpdateOneWithoutCompanyNestedInput> = z.object({
  create: z.union([ z.lazy(() => BlockchainWalletCreateWithoutCompanyInputSchema),z.lazy(() => BlockchainWalletUncheckedCreateWithoutCompanyInputSchema) ]).optional(),
  connectOrCreate: z.lazy(() => BlockchainWalletCreateOrConnectWithoutCompanyInputSchema).optional(),
  upsert: z.lazy(() => BlockchainWalletUpsertWithoutCompanyInputSchema).optional(),
  disconnect: z.union([ z.boolean(),z.lazy(() => BlockchainWalletWhereInputSchema) ]).optional(),
  delete: z.union([ z.boolean(),z.lazy(() => BlockchainWalletWhereInputSchema) ]).optional(),
  connect: z.lazy(() => BlockchainWalletWhereUniqueInputSchema).optional(),
  update: z.union([ z.lazy(() => BlockchainWalletUpdateToOneWithWhereWithoutCompanyInputSchema),z.lazy(() => BlockchainWalletUpdateWithoutCompanyInputSchema),z.lazy(() => BlockchainWalletUncheckedUpdateWithoutCompanyInputSchema) ]).optional(),
}).strict();

export const SigningTemplateUpdateManyWithoutCompanyNestedInputSchema: z.ZodType<Prisma.SigningTemplateUpdateManyWithoutCompanyNestedInput> = z.object({
  create: z.union([ z.lazy(() => SigningTemplateCreateWithoutCompanyInputSchema),z.lazy(() => SigningTemplateCreateWithoutCompanyInputSchema).array(),z.lazy(() => SigningTemplateUncheckedCreateWithoutCompanyInputSchema),z.lazy(() => SigningTemplateUncheckedCreateWithoutCompanyInputSchema).array() ]).optional(),
  connectOrCreate: z.union([ z.lazy(() => SigningTemplateCreateOrConnectWithoutCompanyInputSchema),z.lazy(() => SigningTemplateCreateOrConnectWithoutCompanyInputSchema).array() ]).optional(),
  upsert: z.union([ z.lazy(() => SigningTemplateUpsertWithWhereUniqueWithoutCompanyInputSchema),z.lazy(() => SigningTemplateUpsertWithWhereUniqueWithoutCompanyInputSchema).array() ]).optional(),
  createMany: z.lazy(() => SigningTemplateCreateManyCompanyInputEnvelopeSchema).optional(),
  set: z.union([ z.lazy(() => SigningTemplateWhereUniqueInputSchema),z.lazy(() => SigningTemplateWhereUniqueInputSchema).array() ]).optional(),
  disconnect: z.union([ z.lazy(() => SigningTemplateWhereUniqueInputSchema),z.lazy(() => SigningTemplateWhereUniqueInputSchema).array() ]).optional(),
  delete: z.union([ z.lazy(() => SigningTemplateWhereUniqueInputSchema),z.lazy(() => SigningTemplateWhereUniqueInputSchema).array() ]).optional(),
  connect: z.union([ z.lazy(() => SigningTemplateWhereUniqueInputSchema),z.lazy(() => SigningTemplateWhereUniqueInputSchema).array() ]).optional(),
  update: z.union([ z.lazy(() => SigningTemplateUpdateWithWhereUniqueWithoutCompanyInputSchema),z.lazy(() => SigningTemplateUpdateWithWhereUniqueWithoutCompanyInputSchema).array() ]).optional(),
  updateMany: z.union([ z.lazy(() => SigningTemplateUpdateManyWithWhereWithoutCompanyInputSchema),z.lazy(() => SigningTemplateUpdateManyWithWhereWithoutCompanyInputSchema).array() ]).optional(),
  deleteMany: z.union([ z.lazy(() => SigningTemplateScalarWhereInputSchema),z.lazy(() => SigningTemplateScalarWhereInputSchema).array() ]).optional(),
}).strict();

export const ApiKeyUpdateManyWithoutCompanyNestedInputSchema: z.ZodType<Prisma.ApiKeyUpdateManyWithoutCompanyNestedInput> = z.object({
  create: z.union([ z.lazy(() => ApiKeyCreateWithoutCompanyInputSchema),z.lazy(() => ApiKeyCreateWithoutCompanyInputSchema).array(),z.lazy(() => ApiKeyUncheckedCreateWithoutCompanyInputSchema),z.lazy(() => ApiKeyUncheckedCreateWithoutCompanyInputSchema).array() ]).optional(),
  connectOrCreate: z.union([ z.lazy(() => ApiKeyCreateOrConnectWithoutCompanyInputSchema),z.lazy(() => ApiKeyCreateOrConnectWithoutCompanyInputSchema).array() ]).optional(),
  upsert: z.union([ z.lazy(() => ApiKeyUpsertWithWhereUniqueWithoutCompanyInputSchema),z.lazy(() => ApiKeyUpsertWithWhereUniqueWithoutCompanyInputSchema).array() ]).optional(),
  createMany: z.lazy(() => ApiKeyCreateManyCompanyInputEnvelopeSchema).optional(),
  set: z.union([ z.lazy(() => ApiKeyWhereUniqueInputSchema),z.lazy(() => ApiKeyWhereUniqueInputSchema).array() ]).optional(),
  disconnect: z.union([ z.lazy(() => ApiKeyWhereUniqueInputSchema),z.lazy(() => ApiKeyWhereUniqueInputSchema).array() ]).optional(),
  delete: z.union([ z.lazy(() => ApiKeyWhereUniqueInputSchema),z.lazy(() => ApiKeyWhereUniqueInputSchema).array() ]).optional(),
  connect: z.union([ z.lazy(() => ApiKeyWhereUniqueInputSchema),z.lazy(() => ApiKeyWhereUniqueInputSchema).array() ]).optional(),
  update: z.union([ z.lazy(() => ApiKeyUpdateWithWhereUniqueWithoutCompanyInputSchema),z.lazy(() => ApiKeyUpdateWithWhereUniqueWithoutCompanyInputSchema).array() ]).optional(),
  updateMany: z.union([ z.lazy(() => ApiKeyUpdateManyWithWhereWithoutCompanyInputSchema),z.lazy(() => ApiKeyUpdateManyWithWhereWithoutCompanyInputSchema).array() ]).optional(),
  deleteMany: z.union([ z.lazy(() => ApiKeyScalarWhereInputSchema),z.lazy(() => ApiKeyScalarWhereInputSchema).array() ]).optional(),
}).strict();

export const UserUncheckedUpdateManyWithoutCompanyNestedInputSchema: z.ZodType<Prisma.UserUncheckedUpdateManyWithoutCompanyNestedInput> = z.object({
  create: z.union([ z.lazy(() => UserCreateWithoutCompanyInputSchema),z.lazy(() => UserCreateWithoutCompanyInputSchema).array(),z.lazy(() => UserUncheckedCreateWithoutCompanyInputSchema),z.lazy(() => UserUncheckedCreateWithoutCompanyInputSchema).array() ]).optional(),
  connectOrCreate: z.union([ z.lazy(() => UserCreateOrConnectWithoutCompanyInputSchema),z.lazy(() => UserCreateOrConnectWithoutCompanyInputSchema).array() ]).optional(),
  upsert: z.union([ z.lazy(() => UserUpsertWithWhereUniqueWithoutCompanyInputSchema),z.lazy(() => UserUpsertWithWhereUniqueWithoutCompanyInputSchema).array() ]).optional(),
  createMany: z.lazy(() => UserCreateManyCompanyInputEnvelopeSchema).optional(),
  set: z.union([ z.lazy(() => UserWhereUniqueInputSchema),z.lazy(() => UserWhereUniqueInputSchema).array() ]).optional(),
  disconnect: z.union([ z.lazy(() => UserWhereUniqueInputSchema),z.lazy(() => UserWhereUniqueInputSchema).array() ]).optional(),
  delete: z.union([ z.lazy(() => UserWhereUniqueInputSchema),z.lazy(() => UserWhereUniqueInputSchema).array() ]).optional(),
  connect: z.union([ z.lazy(() => UserWhereUniqueInputSchema),z.lazy(() => UserWhereUniqueInputSchema).array() ]).optional(),
  update: z.union([ z.lazy(() => UserUpdateWithWhereUniqueWithoutCompanyInputSchema),z.lazy(() => UserUpdateWithWhereUniqueWithoutCompanyInputSchema).array() ]).optional(),
  updateMany: z.union([ z.lazy(() => UserUpdateManyWithWhereWithoutCompanyInputSchema),z.lazy(() => UserUpdateManyWithWhereWithoutCompanyInputSchema).array() ]).optional(),
  deleteMany: z.union([ z.lazy(() => UserScalarWhereInputSchema),z.lazy(() => UserScalarWhereInputSchema).array() ]).optional(),
}).strict();

export const DocumentUncheckedUpdateManyWithoutCompanyNestedInputSchema: z.ZodType<Prisma.DocumentUncheckedUpdateManyWithoutCompanyNestedInput> = z.object({
  create: z.union([ z.lazy(() => DocumentCreateWithoutCompanyInputSchema),z.lazy(() => DocumentCreateWithoutCompanyInputSchema).array(),z.lazy(() => DocumentUncheckedCreateWithoutCompanyInputSchema),z.lazy(() => DocumentUncheckedCreateWithoutCompanyInputSchema).array() ]).optional(),
  connectOrCreate: z.union([ z.lazy(() => DocumentCreateOrConnectWithoutCompanyInputSchema),z.lazy(() => DocumentCreateOrConnectWithoutCompanyInputSchema).array() ]).optional(),
  upsert: z.union([ z.lazy(() => DocumentUpsertWithWhereUniqueWithoutCompanyInputSchema),z.lazy(() => DocumentUpsertWithWhereUniqueWithoutCompanyInputSchema).array() ]).optional(),
  createMany: z.lazy(() => DocumentCreateManyCompanyInputEnvelopeSchema).optional(),
  set: z.union([ z.lazy(() => DocumentWhereUniqueInputSchema),z.lazy(() => DocumentWhereUniqueInputSchema).array() ]).optional(),
  disconnect: z.union([ z.lazy(() => DocumentWhereUniqueInputSchema),z.lazy(() => DocumentWhereUniqueInputSchema).array() ]).optional(),
  delete: z.union([ z.lazy(() => DocumentWhereUniqueInputSchema),z.lazy(() => DocumentWhereUniqueInputSchema).array() ]).optional(),
  connect: z.union([ z.lazy(() => DocumentWhereUniqueInputSchema),z.lazy(() => DocumentWhereUniqueInputSchema).array() ]).optional(),
  update: z.union([ z.lazy(() => DocumentUpdateWithWhereUniqueWithoutCompanyInputSchema),z.lazy(() => DocumentUpdateWithWhereUniqueWithoutCompanyInputSchema).array() ]).optional(),
  updateMany: z.union([ z.lazy(() => DocumentUpdateManyWithWhereWithoutCompanyInputSchema),z.lazy(() => DocumentUpdateManyWithWhereWithoutCompanyInputSchema).array() ]).optional(),
  deleteMany: z.union([ z.lazy(() => DocumentScalarWhereInputSchema),z.lazy(() => DocumentScalarWhereInputSchema).array() ]).optional(),
}).strict();

export const CertificateUncheckedUpdateManyWithoutCompanyNestedInputSchema: z.ZodType<Prisma.CertificateUncheckedUpdateManyWithoutCompanyNestedInput> = z.object({
  create: z.union([ z.lazy(() => CertificateCreateWithoutCompanyInputSchema),z.lazy(() => CertificateCreateWithoutCompanyInputSchema).array(),z.lazy(() => CertificateUncheckedCreateWithoutCompanyInputSchema),z.lazy(() => CertificateUncheckedCreateWithoutCompanyInputSchema).array() ]).optional(),
  connectOrCreate: z.union([ z.lazy(() => CertificateCreateOrConnectWithoutCompanyInputSchema),z.lazy(() => CertificateCreateOrConnectWithoutCompanyInputSchema).array() ]).optional(),
  upsert: z.union([ z.lazy(() => CertificateUpsertWithWhereUniqueWithoutCompanyInputSchema),z.lazy(() => CertificateUpsertWithWhereUniqueWithoutCompanyInputSchema).array() ]).optional(),
  createMany: z.lazy(() => CertificateCreateManyCompanyInputEnvelopeSchema).optional(),
  set: z.union([ z.lazy(() => CertificateWhereUniqueInputSchema),z.lazy(() => CertificateWhereUniqueInputSchema).array() ]).optional(),
  disconnect: z.union([ z.lazy(() => CertificateWhereUniqueInputSchema),z.lazy(() => CertificateWhereUniqueInputSchema).array() ]).optional(),
  delete: z.union([ z.lazy(() => CertificateWhereUniqueInputSchema),z.lazy(() => CertificateWhereUniqueInputSchema).array() ]).optional(),
  connect: z.union([ z.lazy(() => CertificateWhereUniqueInputSchema),z.lazy(() => CertificateWhereUniqueInputSchema).array() ]).optional(),
  update: z.union([ z.lazy(() => CertificateUpdateWithWhereUniqueWithoutCompanyInputSchema),z.lazy(() => CertificateUpdateWithWhereUniqueWithoutCompanyInputSchema).array() ]).optional(),
  updateMany: z.union([ z.lazy(() => CertificateUpdateManyWithWhereWithoutCompanyInputSchema),z.lazy(() => CertificateUpdateManyWithWhereWithoutCompanyInputSchema).array() ]).optional(),
  deleteMany: z.union([ z.lazy(() => CertificateScalarWhereInputSchema),z.lazy(() => CertificateScalarWhereInputSchema).array() ]).optional(),
}).strict();

export const BlockchainWalletUncheckedUpdateOneWithoutCompanyNestedInputSchema: z.ZodType<Prisma.BlockchainWalletUncheckedUpdateOneWithoutCompanyNestedInput> = z.object({
  create: z.union([ z.lazy(() => BlockchainWalletCreateWithoutCompanyInputSchema),z.lazy(() => BlockchainWalletUncheckedCreateWithoutCompanyInputSchema) ]).optional(),
  connectOrCreate: z.lazy(() => BlockchainWalletCreateOrConnectWithoutCompanyInputSchema).optional(),
  upsert: z.lazy(() => BlockchainWalletUpsertWithoutCompanyInputSchema).optional(),
  disconnect: z.union([ z.boolean(),z.lazy(() => BlockchainWalletWhereInputSchema) ]).optional(),
  delete: z.union([ z.boolean(),z.lazy(() => BlockchainWalletWhereInputSchema) ]).optional(),
  connect: z.lazy(() => BlockchainWalletWhereUniqueInputSchema).optional(),
  update: z.union([ z.lazy(() => BlockchainWalletUpdateToOneWithWhereWithoutCompanyInputSchema),z.lazy(() => BlockchainWalletUpdateWithoutCompanyInputSchema),z.lazy(() => BlockchainWalletUncheckedUpdateWithoutCompanyInputSchema) ]).optional(),
}).strict();

export const SigningTemplateUncheckedUpdateManyWithoutCompanyNestedInputSchema: z.ZodType<Prisma.SigningTemplateUncheckedUpdateManyWithoutCompanyNestedInput> = z.object({
  create: z.union([ z.lazy(() => SigningTemplateCreateWithoutCompanyInputSchema),z.lazy(() => SigningTemplateCreateWithoutCompanyInputSchema).array(),z.lazy(() => SigningTemplateUncheckedCreateWithoutCompanyInputSchema),z.lazy(() => SigningTemplateUncheckedCreateWithoutCompanyInputSchema).array() ]).optional(),
  connectOrCreate: z.union([ z.lazy(() => SigningTemplateCreateOrConnectWithoutCompanyInputSchema),z.lazy(() => SigningTemplateCreateOrConnectWithoutCompanyInputSchema).array() ]).optional(),
  upsert: z.union([ z.lazy(() => SigningTemplateUpsertWithWhereUniqueWithoutCompanyInputSchema),z.lazy(() => SigningTemplateUpsertWithWhereUniqueWithoutCompanyInputSchema).array() ]).optional(),
  createMany: z.lazy(() => SigningTemplateCreateManyCompanyInputEnvelopeSchema).optional(),
  set: z.union([ z.lazy(() => SigningTemplateWhereUniqueInputSchema),z.lazy(() => SigningTemplateWhereUniqueInputSchema).array() ]).optional(),
  disconnect: z.union([ z.lazy(() => SigningTemplateWhereUniqueInputSchema),z.lazy(() => SigningTemplateWhereUniqueInputSchema).array() ]).optional(),
  delete: z.union([ z.lazy(() => SigningTemplateWhereUniqueInputSchema),z.lazy(() => SigningTemplateWhereUniqueInputSchema).array() ]).optional(),
  connect: z.union([ z.lazy(() => SigningTemplateWhereUniqueInputSchema),z.lazy(() => SigningTemplateWhereUniqueInputSchema).array() ]).optional(),
  update: z.union([ z.lazy(() => SigningTemplateUpdateWithWhereUniqueWithoutCompanyInputSchema),z.lazy(() => SigningTemplateUpdateWithWhereUniqueWithoutCompanyInputSchema).array() ]).optional(),
  updateMany: z.union([ z.lazy(() => SigningTemplateUpdateManyWithWhereWithoutCompanyInputSchema),z.lazy(() => SigningTemplateUpdateManyWithWhereWithoutCompanyInputSchema).array() ]).optional(),
  deleteMany: z.union([ z.lazy(() => SigningTemplateScalarWhereInputSchema),z.lazy(() => SigningTemplateScalarWhereInputSchema).array() ]).optional(),
}).strict();

export const ApiKeyUncheckedUpdateManyWithoutCompanyNestedInputSchema: z.ZodType<Prisma.ApiKeyUncheckedUpdateManyWithoutCompanyNestedInput> = z.object({
  create: z.union([ z.lazy(() => ApiKeyCreateWithoutCompanyInputSchema),z.lazy(() => ApiKeyCreateWithoutCompanyInputSchema).array(),z.lazy(() => ApiKeyUncheckedCreateWithoutCompanyInputSchema),z.lazy(() => ApiKeyUncheckedCreateWithoutCompanyInputSchema).array() ]).optional(),
  connectOrCreate: z.union([ z.lazy(() => ApiKeyCreateOrConnectWithoutCompanyInputSchema),z.lazy(() => ApiKeyCreateOrConnectWithoutCompanyInputSchema).array() ]).optional(),
  upsert: z.union([ z.lazy(() => ApiKeyUpsertWithWhereUniqueWithoutCompanyInputSchema),z.lazy(() => ApiKeyUpsertWithWhereUniqueWithoutCompanyInputSchema).array() ]).optional(),
  createMany: z.lazy(() => ApiKeyCreateManyCompanyInputEnvelopeSchema).optional(),
  set: z.union([ z.lazy(() => ApiKeyWhereUniqueInputSchema),z.lazy(() => ApiKeyWhereUniqueInputSchema).array() ]).optional(),
  disconnect: z.union([ z.lazy(() => ApiKeyWhereUniqueInputSchema),z.lazy(() => ApiKeyWhereUniqueInputSchema).array() ]).optional(),
  delete: z.union([ z.lazy(() => ApiKeyWhereUniqueInputSchema),z.lazy(() => ApiKeyWhereUniqueInputSchema).array() ]).optional(),
  connect: z.union([ z.lazy(() => ApiKeyWhereUniqueInputSchema),z.lazy(() => ApiKeyWhereUniqueInputSchema).array() ]).optional(),
  update: z.union([ z.lazy(() => ApiKeyUpdateWithWhereUniqueWithoutCompanyInputSchema),z.lazy(() => ApiKeyUpdateWithWhereUniqueWithoutCompanyInputSchema).array() ]).optional(),
  updateMany: z.union([ z.lazy(() => ApiKeyUpdateManyWithWhereWithoutCompanyInputSchema),z.lazy(() => ApiKeyUpdateManyWithWhereWithoutCompanyInputSchema).array() ]).optional(),
  deleteMany: z.union([ z.lazy(() => ApiKeyScalarWhereInputSchema),z.lazy(() => ApiKeyScalarWhereInputSchema).array() ]).optional(),
}).strict();

export const UserCreateNestedOneWithoutDocumentsInputSchema: z.ZodType<Prisma.UserCreateNestedOneWithoutDocumentsInput> = z.object({
  create: z.union([ z.lazy(() => UserCreateWithoutDocumentsInputSchema),z.lazy(() => UserUncheckedCreateWithoutDocumentsInputSchema) ]).optional(),
  connectOrCreate: z.lazy(() => UserCreateOrConnectWithoutDocumentsInputSchema).optional(),
  connect: z.lazy(() => UserWhereUniqueInputSchema).optional()
}).strict();

export const CompanyCreateNestedOneWithoutDocumentsInputSchema: z.ZodType<Prisma.CompanyCreateNestedOneWithoutDocumentsInput> = z.object({
  create: z.union([ z.lazy(() => CompanyCreateWithoutDocumentsInputSchema),z.lazy(() => CompanyUncheckedCreateWithoutDocumentsInputSchema) ]).optional(),
  connectOrCreate: z.lazy(() => CompanyCreateOrConnectWithoutDocumentsInputSchema).optional(),
  connect: z.lazy(() => CompanyWhereUniqueInputSchema).optional()
}).strict();

export const SigningTemplateCreateNestedOneWithoutDocumentsInputSchema: z.ZodType<Prisma.SigningTemplateCreateNestedOneWithoutDocumentsInput> = z.object({
  create: z.union([ z.lazy(() => SigningTemplateCreateWithoutDocumentsInputSchema),z.lazy(() => SigningTemplateUncheckedCreateWithoutDocumentsInputSchema) ]).optional(),
  connectOrCreate: z.lazy(() => SigningTemplateCreateOrConnectWithoutDocumentsInputSchema).optional(),
  connect: z.lazy(() => SigningTemplateWhereUniqueInputSchema).optional()
}).strict();

export const DocumentSignerCreateNestedManyWithoutDocumentInputSchema: z.ZodType<Prisma.DocumentSignerCreateNestedManyWithoutDocumentInput> = z.object({
  create: z.union([ z.lazy(() => DocumentSignerCreateWithoutDocumentInputSchema),z.lazy(() => DocumentSignerCreateWithoutDocumentInputSchema).array(),z.lazy(() => DocumentSignerUncheckedCreateWithoutDocumentInputSchema),z.lazy(() => DocumentSignerUncheckedCreateWithoutDocumentInputSchema).array() ]).optional(),
  connectOrCreate: z.union([ z.lazy(() => DocumentSignerCreateOrConnectWithoutDocumentInputSchema),z.lazy(() => DocumentSignerCreateOrConnectWithoutDocumentInputSchema).array() ]).optional(),
  createMany: z.lazy(() => DocumentSignerCreateManyDocumentInputEnvelopeSchema).optional(),
  connect: z.union([ z.lazy(() => DocumentSignerWhereUniqueInputSchema),z.lazy(() => DocumentSignerWhereUniqueInputSchema).array() ]).optional(),
}).strict();

export const SignatureCreateNestedManyWithoutDocumentInputSchema: z.ZodType<Prisma.SignatureCreateNestedManyWithoutDocumentInput> = z.object({
  create: z.union([ z.lazy(() => SignatureCreateWithoutDocumentInputSchema),z.lazy(() => SignatureCreateWithoutDocumentInputSchema).array(),z.lazy(() => SignatureUncheckedCreateWithoutDocumentInputSchema),z.lazy(() => SignatureUncheckedCreateWithoutDocumentInputSchema).array() ]).optional(),
  connectOrCreate: z.union([ z.lazy(() => SignatureCreateOrConnectWithoutDocumentInputSchema),z.lazy(() => SignatureCreateOrConnectWithoutDocumentInputSchema).array() ]).optional(),
  createMany: z.lazy(() => SignatureCreateManyDocumentInputEnvelopeSchema).optional(),
  connect: z.union([ z.lazy(() => SignatureWhereUniqueInputSchema),z.lazy(() => SignatureWhereUniqueInputSchema).array() ]).optional(),
}).strict();

export const AuditLogCreateNestedManyWithoutDocumentInputSchema: z.ZodType<Prisma.AuditLogCreateNestedManyWithoutDocumentInput> = z.object({
  create: z.union([ z.lazy(() => AuditLogCreateWithoutDocumentInputSchema),z.lazy(() => AuditLogCreateWithoutDocumentInputSchema).array(),z.lazy(() => AuditLogUncheckedCreateWithoutDocumentInputSchema),z.lazy(() => AuditLogUncheckedCreateWithoutDocumentInputSchema).array() ]).optional(),
  connectOrCreate: z.union([ z.lazy(() => AuditLogCreateOrConnectWithoutDocumentInputSchema),z.lazy(() => AuditLogCreateOrConnectWithoutDocumentInputSchema).array() ]).optional(),
  createMany: z.lazy(() => AuditLogCreateManyDocumentInputEnvelopeSchema).optional(),
  connect: z.union([ z.lazy(() => AuditLogWhereUniqueInputSchema),z.lazy(() => AuditLogWhereUniqueInputSchema).array() ]).optional(),
}).strict();

export const SignatureFieldCreateNestedManyWithoutDocumentInputSchema: z.ZodType<Prisma.SignatureFieldCreateNestedManyWithoutDocumentInput> = z.object({
  create: z.union([ z.lazy(() => SignatureFieldCreateWithoutDocumentInputSchema),z.lazy(() => SignatureFieldCreateWithoutDocumentInputSchema).array(),z.lazy(() => SignatureFieldUncheckedCreateWithoutDocumentInputSchema),z.lazy(() => SignatureFieldUncheckedCreateWithoutDocumentInputSchema).array() ]).optional(),
  connectOrCreate: z.union([ z.lazy(() => SignatureFieldCreateOrConnectWithoutDocumentInputSchema),z.lazy(() => SignatureFieldCreateOrConnectWithoutDocumentInputSchema).array() ]).optional(),
  createMany: z.lazy(() => SignatureFieldCreateManyDocumentInputEnvelopeSchema).optional(),
  connect: z.union([ z.lazy(() => SignatureFieldWhereUniqueInputSchema),z.lazy(() => SignatureFieldWhereUniqueInputSchema).array() ]).optional(),
}).strict();

export const DocumentSignerUncheckedCreateNestedManyWithoutDocumentInputSchema: z.ZodType<Prisma.DocumentSignerUncheckedCreateNestedManyWithoutDocumentInput> = z.object({
  create: z.union([ z.lazy(() => DocumentSignerCreateWithoutDocumentInputSchema),z.lazy(() => DocumentSignerCreateWithoutDocumentInputSchema).array(),z.lazy(() => DocumentSignerUncheckedCreateWithoutDocumentInputSchema),z.lazy(() => DocumentSignerUncheckedCreateWithoutDocumentInputSchema).array() ]).optional(),
  connectOrCreate: z.union([ z.lazy(() => DocumentSignerCreateOrConnectWithoutDocumentInputSchema),z.lazy(() => DocumentSignerCreateOrConnectWithoutDocumentInputSchema).array() ]).optional(),
  createMany: z.lazy(() => DocumentSignerCreateManyDocumentInputEnvelopeSchema).optional(),
  connect: z.union([ z.lazy(() => DocumentSignerWhereUniqueInputSchema),z.lazy(() => DocumentSignerWhereUniqueInputSchema).array() ]).optional(),
}).strict();

export const SignatureUncheckedCreateNestedManyWithoutDocumentInputSchema: z.ZodType<Prisma.SignatureUncheckedCreateNestedManyWithoutDocumentInput> = z.object({
  create: z.union([ z.lazy(() => SignatureCreateWithoutDocumentInputSchema),z.lazy(() => SignatureCreateWithoutDocumentInputSchema).array(),z.lazy(() => SignatureUncheckedCreateWithoutDocumentInputSchema),z.lazy(() => SignatureUncheckedCreateWithoutDocumentInputSchema).array() ]).optional(),
  connectOrCreate: z.union([ z.lazy(() => SignatureCreateOrConnectWithoutDocumentInputSchema),z.lazy(() => SignatureCreateOrConnectWithoutDocumentInputSchema).array() ]).optional(),
  createMany: z.lazy(() => SignatureCreateManyDocumentInputEnvelopeSchema).optional(),
  connect: z.union([ z.lazy(() => SignatureWhereUniqueInputSchema),z.lazy(() => SignatureWhereUniqueInputSchema).array() ]).optional(),
}).strict();

export const AuditLogUncheckedCreateNestedManyWithoutDocumentInputSchema: z.ZodType<Prisma.AuditLogUncheckedCreateNestedManyWithoutDocumentInput> = z.object({
  create: z.union([ z.lazy(() => AuditLogCreateWithoutDocumentInputSchema),z.lazy(() => AuditLogCreateWithoutDocumentInputSchema).array(),z.lazy(() => AuditLogUncheckedCreateWithoutDocumentInputSchema),z.lazy(() => AuditLogUncheckedCreateWithoutDocumentInputSchema).array() ]).optional(),
  connectOrCreate: z.union([ z.lazy(() => AuditLogCreateOrConnectWithoutDocumentInputSchema),z.lazy(() => AuditLogCreateOrConnectWithoutDocumentInputSchema).array() ]).optional(),
  createMany: z.lazy(() => AuditLogCreateManyDocumentInputEnvelopeSchema).optional(),
  connect: z.union([ z.lazy(() => AuditLogWhereUniqueInputSchema),z.lazy(() => AuditLogWhereUniqueInputSchema).array() ]).optional(),
}).strict();

export const SignatureFieldUncheckedCreateNestedManyWithoutDocumentInputSchema: z.ZodType<Prisma.SignatureFieldUncheckedCreateNestedManyWithoutDocumentInput> = z.object({
  create: z.union([ z.lazy(() => SignatureFieldCreateWithoutDocumentInputSchema),z.lazy(() => SignatureFieldCreateWithoutDocumentInputSchema).array(),z.lazy(() => SignatureFieldUncheckedCreateWithoutDocumentInputSchema),z.lazy(() => SignatureFieldUncheckedCreateWithoutDocumentInputSchema).array() ]).optional(),
  connectOrCreate: z.union([ z.lazy(() => SignatureFieldCreateOrConnectWithoutDocumentInputSchema),z.lazy(() => SignatureFieldCreateOrConnectWithoutDocumentInputSchema).array() ]).optional(),
  createMany: z.lazy(() => SignatureFieldCreateManyDocumentInputEnvelopeSchema).optional(),
  connect: z.union([ z.lazy(() => SignatureFieldWhereUniqueInputSchema),z.lazy(() => SignatureFieldWhereUniqueInputSchema).array() ]).optional(),
}).strict();

export const EnumDocumentStatusFieldUpdateOperationsInputSchema: z.ZodType<Prisma.EnumDocumentStatusFieldUpdateOperationsInput> = z.object({
  set: z.lazy(() => DocumentStatusSchema).optional()
}).strict();

export const NullableDateTimeFieldUpdateOperationsInputSchema: z.ZodType<Prisma.NullableDateTimeFieldUpdateOperationsInput> = z.object({
  set: z.coerce.date().optional().nullable()
}).strict();

export const UserUpdateOneRequiredWithoutDocumentsNestedInputSchema: z.ZodType<Prisma.UserUpdateOneRequiredWithoutDocumentsNestedInput> = z.object({
  create: z.union([ z.lazy(() => UserCreateWithoutDocumentsInputSchema),z.lazy(() => UserUncheckedCreateWithoutDocumentsInputSchema) ]).optional(),
  connectOrCreate: z.lazy(() => UserCreateOrConnectWithoutDocumentsInputSchema).optional(),
  upsert: z.lazy(() => UserUpsertWithoutDocumentsInputSchema).optional(),
  connect: z.lazy(() => UserWhereUniqueInputSchema).optional(),
  update: z.union([ z.lazy(() => UserUpdateToOneWithWhereWithoutDocumentsInputSchema),z.lazy(() => UserUpdateWithoutDocumentsInputSchema),z.lazy(() => UserUncheckedUpdateWithoutDocumentsInputSchema) ]).optional(),
}).strict();

export const CompanyUpdateOneRequiredWithoutDocumentsNestedInputSchema: z.ZodType<Prisma.CompanyUpdateOneRequiredWithoutDocumentsNestedInput> = z.object({
  create: z.union([ z.lazy(() => CompanyCreateWithoutDocumentsInputSchema),z.lazy(() => CompanyUncheckedCreateWithoutDocumentsInputSchema) ]).optional(),
  connectOrCreate: z.lazy(() => CompanyCreateOrConnectWithoutDocumentsInputSchema).optional(),
  upsert: z.lazy(() => CompanyUpsertWithoutDocumentsInputSchema).optional(),
  connect: z.lazy(() => CompanyWhereUniqueInputSchema).optional(),
  update: z.union([ z.lazy(() => CompanyUpdateToOneWithWhereWithoutDocumentsInputSchema),z.lazy(() => CompanyUpdateWithoutDocumentsInputSchema),z.lazy(() => CompanyUncheckedUpdateWithoutDocumentsInputSchema) ]).optional(),
}).strict();

export const SigningTemplateUpdateOneWithoutDocumentsNestedInputSchema: z.ZodType<Prisma.SigningTemplateUpdateOneWithoutDocumentsNestedInput> = z.object({
  create: z.union([ z.lazy(() => SigningTemplateCreateWithoutDocumentsInputSchema),z.lazy(() => SigningTemplateUncheckedCreateWithoutDocumentsInputSchema) ]).optional(),
  connectOrCreate: z.lazy(() => SigningTemplateCreateOrConnectWithoutDocumentsInputSchema).optional(),
  upsert: z.lazy(() => SigningTemplateUpsertWithoutDocumentsInputSchema).optional(),
  disconnect: z.union([ z.boolean(),z.lazy(() => SigningTemplateWhereInputSchema) ]).optional(),
  delete: z.union([ z.boolean(),z.lazy(() => SigningTemplateWhereInputSchema) ]).optional(),
  connect: z.lazy(() => SigningTemplateWhereUniqueInputSchema).optional(),
  update: z.union([ z.lazy(() => SigningTemplateUpdateToOneWithWhereWithoutDocumentsInputSchema),z.lazy(() => SigningTemplateUpdateWithoutDocumentsInputSchema),z.lazy(() => SigningTemplateUncheckedUpdateWithoutDocumentsInputSchema) ]).optional(),
}).strict();

export const DocumentSignerUpdateManyWithoutDocumentNestedInputSchema: z.ZodType<Prisma.DocumentSignerUpdateManyWithoutDocumentNestedInput> = z.object({
  create: z.union([ z.lazy(() => DocumentSignerCreateWithoutDocumentInputSchema),z.lazy(() => DocumentSignerCreateWithoutDocumentInputSchema).array(),z.lazy(() => DocumentSignerUncheckedCreateWithoutDocumentInputSchema),z.lazy(() => DocumentSignerUncheckedCreateWithoutDocumentInputSchema).array() ]).optional(),
  connectOrCreate: z.union([ z.lazy(() => DocumentSignerCreateOrConnectWithoutDocumentInputSchema),z.lazy(() => DocumentSignerCreateOrConnectWithoutDocumentInputSchema).array() ]).optional(),
  upsert: z.union([ z.lazy(() => DocumentSignerUpsertWithWhereUniqueWithoutDocumentInputSchema),z.lazy(() => DocumentSignerUpsertWithWhereUniqueWithoutDocumentInputSchema).array() ]).optional(),
  createMany: z.lazy(() => DocumentSignerCreateManyDocumentInputEnvelopeSchema).optional(),
  set: z.union([ z.lazy(() => DocumentSignerWhereUniqueInputSchema),z.lazy(() => DocumentSignerWhereUniqueInputSchema).array() ]).optional(),
  disconnect: z.union([ z.lazy(() => DocumentSignerWhereUniqueInputSchema),z.lazy(() => DocumentSignerWhereUniqueInputSchema).array() ]).optional(),
  delete: z.union([ z.lazy(() => DocumentSignerWhereUniqueInputSchema),z.lazy(() => DocumentSignerWhereUniqueInputSchema).array() ]).optional(),
  connect: z.union([ z.lazy(() => DocumentSignerWhereUniqueInputSchema),z.lazy(() => DocumentSignerWhereUniqueInputSchema).array() ]).optional(),
  update: z.union([ z.lazy(() => DocumentSignerUpdateWithWhereUniqueWithoutDocumentInputSchema),z.lazy(() => DocumentSignerUpdateWithWhereUniqueWithoutDocumentInputSchema).array() ]).optional(),
  updateMany: z.union([ z.lazy(() => DocumentSignerUpdateManyWithWhereWithoutDocumentInputSchema),z.lazy(() => DocumentSignerUpdateManyWithWhereWithoutDocumentInputSchema).array() ]).optional(),
  deleteMany: z.union([ z.lazy(() => DocumentSignerScalarWhereInputSchema),z.lazy(() => DocumentSignerScalarWhereInputSchema).array() ]).optional(),
}).strict();

export const SignatureUpdateManyWithoutDocumentNestedInputSchema: z.ZodType<Prisma.SignatureUpdateManyWithoutDocumentNestedInput> = z.object({
  create: z.union([ z.lazy(() => SignatureCreateWithoutDocumentInputSchema),z.lazy(() => SignatureCreateWithoutDocumentInputSchema).array(),z.lazy(() => SignatureUncheckedCreateWithoutDocumentInputSchema),z.lazy(() => SignatureUncheckedCreateWithoutDocumentInputSchema).array() ]).optional(),
  connectOrCreate: z.union([ z.lazy(() => SignatureCreateOrConnectWithoutDocumentInputSchema),z.lazy(() => SignatureCreateOrConnectWithoutDocumentInputSchema).array() ]).optional(),
  upsert: z.union([ z.lazy(() => SignatureUpsertWithWhereUniqueWithoutDocumentInputSchema),z.lazy(() => SignatureUpsertWithWhereUniqueWithoutDocumentInputSchema).array() ]).optional(),
  createMany: z.lazy(() => SignatureCreateManyDocumentInputEnvelopeSchema).optional(),
  set: z.union([ z.lazy(() => SignatureWhereUniqueInputSchema),z.lazy(() => SignatureWhereUniqueInputSchema).array() ]).optional(),
  disconnect: z.union([ z.lazy(() => SignatureWhereUniqueInputSchema),z.lazy(() => SignatureWhereUniqueInputSchema).array() ]).optional(),
  delete: z.union([ z.lazy(() => SignatureWhereUniqueInputSchema),z.lazy(() => SignatureWhereUniqueInputSchema).array() ]).optional(),
  connect: z.union([ z.lazy(() => SignatureWhereUniqueInputSchema),z.lazy(() => SignatureWhereUniqueInputSchema).array() ]).optional(),
  update: z.union([ z.lazy(() => SignatureUpdateWithWhereUniqueWithoutDocumentInputSchema),z.lazy(() => SignatureUpdateWithWhereUniqueWithoutDocumentInputSchema).array() ]).optional(),
  updateMany: z.union([ z.lazy(() => SignatureUpdateManyWithWhereWithoutDocumentInputSchema),z.lazy(() => SignatureUpdateManyWithWhereWithoutDocumentInputSchema).array() ]).optional(),
  deleteMany: z.union([ z.lazy(() => SignatureScalarWhereInputSchema),z.lazy(() => SignatureScalarWhereInputSchema).array() ]).optional(),
}).strict();

export const AuditLogUpdateManyWithoutDocumentNestedInputSchema: z.ZodType<Prisma.AuditLogUpdateManyWithoutDocumentNestedInput> = z.object({
  create: z.union([ z.lazy(() => AuditLogCreateWithoutDocumentInputSchema),z.lazy(() => AuditLogCreateWithoutDocumentInputSchema).array(),z.lazy(() => AuditLogUncheckedCreateWithoutDocumentInputSchema),z.lazy(() => AuditLogUncheckedCreateWithoutDocumentInputSchema).array() ]).optional(),
  connectOrCreate: z.union([ z.lazy(() => AuditLogCreateOrConnectWithoutDocumentInputSchema),z.lazy(() => AuditLogCreateOrConnectWithoutDocumentInputSchema).array() ]).optional(),
  upsert: z.union([ z.lazy(() => AuditLogUpsertWithWhereUniqueWithoutDocumentInputSchema),z.lazy(() => AuditLogUpsertWithWhereUniqueWithoutDocumentInputSchema).array() ]).optional(),
  createMany: z.lazy(() => AuditLogCreateManyDocumentInputEnvelopeSchema).optional(),
  set: z.union([ z.lazy(() => AuditLogWhereUniqueInputSchema),z.lazy(() => AuditLogWhereUniqueInputSchema).array() ]).optional(),
  disconnect: z.union([ z.lazy(() => AuditLogWhereUniqueInputSchema),z.lazy(() => AuditLogWhereUniqueInputSchema).array() ]).optional(),
  delete: z.union([ z.lazy(() => AuditLogWhereUniqueInputSchema),z.lazy(() => AuditLogWhereUniqueInputSchema).array() ]).optional(),
  connect: z.union([ z.lazy(() => AuditLogWhereUniqueInputSchema),z.lazy(() => AuditLogWhereUniqueInputSchema).array() ]).optional(),
  update: z.union([ z.lazy(() => AuditLogUpdateWithWhereUniqueWithoutDocumentInputSchema),z.lazy(() => AuditLogUpdateWithWhereUniqueWithoutDocumentInputSchema).array() ]).optional(),
  updateMany: z.union([ z.lazy(() => AuditLogUpdateManyWithWhereWithoutDocumentInputSchema),z.lazy(() => AuditLogUpdateManyWithWhereWithoutDocumentInputSchema).array() ]).optional(),
  deleteMany: z.union([ z.lazy(() => AuditLogScalarWhereInputSchema),z.lazy(() => AuditLogScalarWhereInputSchema).array() ]).optional(),
}).strict();

export const SignatureFieldUpdateManyWithoutDocumentNestedInputSchema: z.ZodType<Prisma.SignatureFieldUpdateManyWithoutDocumentNestedInput> = z.object({
  create: z.union([ z.lazy(() => SignatureFieldCreateWithoutDocumentInputSchema),z.lazy(() => SignatureFieldCreateWithoutDocumentInputSchema).array(),z.lazy(() => SignatureFieldUncheckedCreateWithoutDocumentInputSchema),z.lazy(() => SignatureFieldUncheckedCreateWithoutDocumentInputSchema).array() ]).optional(),
  connectOrCreate: z.union([ z.lazy(() => SignatureFieldCreateOrConnectWithoutDocumentInputSchema),z.lazy(() => SignatureFieldCreateOrConnectWithoutDocumentInputSchema).array() ]).optional(),
  upsert: z.union([ z.lazy(() => SignatureFieldUpsertWithWhereUniqueWithoutDocumentInputSchema),z.lazy(() => SignatureFieldUpsertWithWhereUniqueWithoutDocumentInputSchema).array() ]).optional(),
  createMany: z.lazy(() => SignatureFieldCreateManyDocumentInputEnvelopeSchema).optional(),
  set: z.union([ z.lazy(() => SignatureFieldWhereUniqueInputSchema),z.lazy(() => SignatureFieldWhereUniqueInputSchema).array() ]).optional(),
  disconnect: z.union([ z.lazy(() => SignatureFieldWhereUniqueInputSchema),z.lazy(() => SignatureFieldWhereUniqueInputSchema).array() ]).optional(),
  delete: z.union([ z.lazy(() => SignatureFieldWhereUniqueInputSchema),z.lazy(() => SignatureFieldWhereUniqueInputSchema).array() ]).optional(),
  connect: z.union([ z.lazy(() => SignatureFieldWhereUniqueInputSchema),z.lazy(() => SignatureFieldWhereUniqueInputSchema).array() ]).optional(),
  update: z.union([ z.lazy(() => SignatureFieldUpdateWithWhereUniqueWithoutDocumentInputSchema),z.lazy(() => SignatureFieldUpdateWithWhereUniqueWithoutDocumentInputSchema).array() ]).optional(),
  updateMany: z.union([ z.lazy(() => SignatureFieldUpdateManyWithWhereWithoutDocumentInputSchema),z.lazy(() => SignatureFieldUpdateManyWithWhereWithoutDocumentInputSchema).array() ]).optional(),
  deleteMany: z.union([ z.lazy(() => SignatureFieldScalarWhereInputSchema),z.lazy(() => SignatureFieldScalarWhereInputSchema).array() ]).optional(),
}).strict();

export const DocumentSignerUncheckedUpdateManyWithoutDocumentNestedInputSchema: z.ZodType<Prisma.DocumentSignerUncheckedUpdateManyWithoutDocumentNestedInput> = z.object({
  create: z.union([ z.lazy(() => DocumentSignerCreateWithoutDocumentInputSchema),z.lazy(() => DocumentSignerCreateWithoutDocumentInputSchema).array(),z.lazy(() => DocumentSignerUncheckedCreateWithoutDocumentInputSchema),z.lazy(() => DocumentSignerUncheckedCreateWithoutDocumentInputSchema).array() ]).optional(),
  connectOrCreate: z.union([ z.lazy(() => DocumentSignerCreateOrConnectWithoutDocumentInputSchema),z.lazy(() => DocumentSignerCreateOrConnectWithoutDocumentInputSchema).array() ]).optional(),
  upsert: z.union([ z.lazy(() => DocumentSignerUpsertWithWhereUniqueWithoutDocumentInputSchema),z.lazy(() => DocumentSignerUpsertWithWhereUniqueWithoutDocumentInputSchema).array() ]).optional(),
  createMany: z.lazy(() => DocumentSignerCreateManyDocumentInputEnvelopeSchema).optional(),
  set: z.union([ z.lazy(() => DocumentSignerWhereUniqueInputSchema),z.lazy(() => DocumentSignerWhereUniqueInputSchema).array() ]).optional(),
  disconnect: z.union([ z.lazy(() => DocumentSignerWhereUniqueInputSchema),z.lazy(() => DocumentSignerWhereUniqueInputSchema).array() ]).optional(),
  delete: z.union([ z.lazy(() => DocumentSignerWhereUniqueInputSchema),z.lazy(() => DocumentSignerWhereUniqueInputSchema).array() ]).optional(),
  connect: z.union([ z.lazy(() => DocumentSignerWhereUniqueInputSchema),z.lazy(() => DocumentSignerWhereUniqueInputSchema).array() ]).optional(),
  update: z.union([ z.lazy(() => DocumentSignerUpdateWithWhereUniqueWithoutDocumentInputSchema),z.lazy(() => DocumentSignerUpdateWithWhereUniqueWithoutDocumentInputSchema).array() ]).optional(),
  updateMany: z.union([ z.lazy(() => DocumentSignerUpdateManyWithWhereWithoutDocumentInputSchema),z.lazy(() => DocumentSignerUpdateManyWithWhereWithoutDocumentInputSchema).array() ]).optional(),
  deleteMany: z.union([ z.lazy(() => DocumentSignerScalarWhereInputSchema),z.lazy(() => DocumentSignerScalarWhereInputSchema).array() ]).optional(),
}).strict();

export const SignatureUncheckedUpdateManyWithoutDocumentNestedInputSchema: z.ZodType<Prisma.SignatureUncheckedUpdateManyWithoutDocumentNestedInput> = z.object({
  create: z.union([ z.lazy(() => SignatureCreateWithoutDocumentInputSchema),z.lazy(() => SignatureCreateWithoutDocumentInputSchema).array(),z.lazy(() => SignatureUncheckedCreateWithoutDocumentInputSchema),z.lazy(() => SignatureUncheckedCreateWithoutDocumentInputSchema).array() ]).optional(),
  connectOrCreate: z.union([ z.lazy(() => SignatureCreateOrConnectWithoutDocumentInputSchema),z.lazy(() => SignatureCreateOrConnectWithoutDocumentInputSchema).array() ]).optional(),
  upsert: z.union([ z.lazy(() => SignatureUpsertWithWhereUniqueWithoutDocumentInputSchema),z.lazy(() => SignatureUpsertWithWhereUniqueWithoutDocumentInputSchema).array() ]).optional(),
  createMany: z.lazy(() => SignatureCreateManyDocumentInputEnvelopeSchema).optional(),
  set: z.union([ z.lazy(() => SignatureWhereUniqueInputSchema),z.lazy(() => SignatureWhereUniqueInputSchema).array() ]).optional(),
  disconnect: z.union([ z.lazy(() => SignatureWhereUniqueInputSchema),z.lazy(() => SignatureWhereUniqueInputSchema).array() ]).optional(),
  delete: z.union([ z.lazy(() => SignatureWhereUniqueInputSchema),z.lazy(() => SignatureWhereUniqueInputSchema).array() ]).optional(),
  connect: z.union([ z.lazy(() => SignatureWhereUniqueInputSchema),z.lazy(() => SignatureWhereUniqueInputSchema).array() ]).optional(),
  update: z.union([ z.lazy(() => SignatureUpdateWithWhereUniqueWithoutDocumentInputSchema),z.lazy(() => SignatureUpdateWithWhereUniqueWithoutDocumentInputSchema).array() ]).optional(),
  updateMany: z.union([ z.lazy(() => SignatureUpdateManyWithWhereWithoutDocumentInputSchema),z.lazy(() => SignatureUpdateManyWithWhereWithoutDocumentInputSchema).array() ]).optional(),
  deleteMany: z.union([ z.lazy(() => SignatureScalarWhereInputSchema),z.lazy(() => SignatureScalarWhereInputSchema).array() ]).optional(),
}).strict();

export const AuditLogUncheckedUpdateManyWithoutDocumentNestedInputSchema: z.ZodType<Prisma.AuditLogUncheckedUpdateManyWithoutDocumentNestedInput> = z.object({
  create: z.union([ z.lazy(() => AuditLogCreateWithoutDocumentInputSchema),z.lazy(() => AuditLogCreateWithoutDocumentInputSchema).array(),z.lazy(() => AuditLogUncheckedCreateWithoutDocumentInputSchema),z.lazy(() => AuditLogUncheckedCreateWithoutDocumentInputSchema).array() ]).optional(),
  connectOrCreate: z.union([ z.lazy(() => AuditLogCreateOrConnectWithoutDocumentInputSchema),z.lazy(() => AuditLogCreateOrConnectWithoutDocumentInputSchema).array() ]).optional(),
  upsert: z.union([ z.lazy(() => AuditLogUpsertWithWhereUniqueWithoutDocumentInputSchema),z.lazy(() => AuditLogUpsertWithWhereUniqueWithoutDocumentInputSchema).array() ]).optional(),
  createMany: z.lazy(() => AuditLogCreateManyDocumentInputEnvelopeSchema).optional(),
  set: z.union([ z.lazy(() => AuditLogWhereUniqueInputSchema),z.lazy(() => AuditLogWhereUniqueInputSchema).array() ]).optional(),
  disconnect: z.union([ z.lazy(() => AuditLogWhereUniqueInputSchema),z.lazy(() => AuditLogWhereUniqueInputSchema).array() ]).optional(),
  delete: z.union([ z.lazy(() => AuditLogWhereUniqueInputSchema),z.lazy(() => AuditLogWhereUniqueInputSchema).array() ]).optional(),
  connect: z.union([ z.lazy(() => AuditLogWhereUniqueInputSchema),z.lazy(() => AuditLogWhereUniqueInputSchema).array() ]).optional(),
  update: z.union([ z.lazy(() => AuditLogUpdateWithWhereUniqueWithoutDocumentInputSchema),z.lazy(() => AuditLogUpdateWithWhereUniqueWithoutDocumentInputSchema).array() ]).optional(),
  updateMany: z.union([ z.lazy(() => AuditLogUpdateManyWithWhereWithoutDocumentInputSchema),z.lazy(() => AuditLogUpdateManyWithWhereWithoutDocumentInputSchema).array() ]).optional(),
  deleteMany: z.union([ z.lazy(() => AuditLogScalarWhereInputSchema),z.lazy(() => AuditLogScalarWhereInputSchema).array() ]).optional(),
}).strict();

export const SignatureFieldUncheckedUpdateManyWithoutDocumentNestedInputSchema: z.ZodType<Prisma.SignatureFieldUncheckedUpdateManyWithoutDocumentNestedInput> = z.object({
  create: z.union([ z.lazy(() => SignatureFieldCreateWithoutDocumentInputSchema),z.lazy(() => SignatureFieldCreateWithoutDocumentInputSchema).array(),z.lazy(() => SignatureFieldUncheckedCreateWithoutDocumentInputSchema),z.lazy(() => SignatureFieldUncheckedCreateWithoutDocumentInputSchema).array() ]).optional(),
  connectOrCreate: z.union([ z.lazy(() => SignatureFieldCreateOrConnectWithoutDocumentInputSchema),z.lazy(() => SignatureFieldCreateOrConnectWithoutDocumentInputSchema).array() ]).optional(),
  upsert: z.union([ z.lazy(() => SignatureFieldUpsertWithWhereUniqueWithoutDocumentInputSchema),z.lazy(() => SignatureFieldUpsertWithWhereUniqueWithoutDocumentInputSchema).array() ]).optional(),
  createMany: z.lazy(() => SignatureFieldCreateManyDocumentInputEnvelopeSchema).optional(),
  set: z.union([ z.lazy(() => SignatureFieldWhereUniqueInputSchema),z.lazy(() => SignatureFieldWhereUniqueInputSchema).array() ]).optional(),
  disconnect: z.union([ z.lazy(() => SignatureFieldWhereUniqueInputSchema),z.lazy(() => SignatureFieldWhereUniqueInputSchema).array() ]).optional(),
  delete: z.union([ z.lazy(() => SignatureFieldWhereUniqueInputSchema),z.lazy(() => SignatureFieldWhereUniqueInputSchema).array() ]).optional(),
  connect: z.union([ z.lazy(() => SignatureFieldWhereUniqueInputSchema),z.lazy(() => SignatureFieldWhereUniqueInputSchema).array() ]).optional(),
  update: z.union([ z.lazy(() => SignatureFieldUpdateWithWhereUniqueWithoutDocumentInputSchema),z.lazy(() => SignatureFieldUpdateWithWhereUniqueWithoutDocumentInputSchema).array() ]).optional(),
  updateMany: z.union([ z.lazy(() => SignatureFieldUpdateManyWithWhereWithoutDocumentInputSchema),z.lazy(() => SignatureFieldUpdateManyWithWhereWithoutDocumentInputSchema).array() ]).optional(),
  deleteMany: z.union([ z.lazy(() => SignatureFieldScalarWhereInputSchema),z.lazy(() => SignatureFieldScalarWhereInputSchema).array() ]).optional(),
}).strict();

export const DocumentCreateNestedOneWithoutSignersInputSchema: z.ZodType<Prisma.DocumentCreateNestedOneWithoutSignersInput> = z.object({
  create: z.union([ z.lazy(() => DocumentCreateWithoutSignersInputSchema),z.lazy(() => DocumentUncheckedCreateWithoutSignersInputSchema) ]).optional(),
  connectOrCreate: z.lazy(() => DocumentCreateOrConnectWithoutSignersInputSchema).optional(),
  connect: z.lazy(() => DocumentWhereUniqueInputSchema).optional()
}).strict();

export const SignatureFieldCreateNestedManyWithoutSignerInputSchema: z.ZodType<Prisma.SignatureFieldCreateNestedManyWithoutSignerInput> = z.object({
  create: z.union([ z.lazy(() => SignatureFieldCreateWithoutSignerInputSchema),z.lazy(() => SignatureFieldCreateWithoutSignerInputSchema).array(),z.lazy(() => SignatureFieldUncheckedCreateWithoutSignerInputSchema),z.lazy(() => SignatureFieldUncheckedCreateWithoutSignerInputSchema).array() ]).optional(),
  connectOrCreate: z.union([ z.lazy(() => SignatureFieldCreateOrConnectWithoutSignerInputSchema),z.lazy(() => SignatureFieldCreateOrConnectWithoutSignerInputSchema).array() ]).optional(),
  createMany: z.lazy(() => SignatureFieldCreateManySignerInputEnvelopeSchema).optional(),
  connect: z.union([ z.lazy(() => SignatureFieldWhereUniqueInputSchema),z.lazy(() => SignatureFieldWhereUniqueInputSchema).array() ]).optional(),
}).strict();

export const SignatureCreateNestedOneWithoutDocumentSignerInputSchema: z.ZodType<Prisma.SignatureCreateNestedOneWithoutDocumentSignerInput> = z.object({
  create: z.union([ z.lazy(() => SignatureCreateWithoutDocumentSignerInputSchema),z.lazy(() => SignatureUncheckedCreateWithoutDocumentSignerInputSchema) ]).optional(),
  connectOrCreate: z.lazy(() => SignatureCreateOrConnectWithoutDocumentSignerInputSchema).optional(),
  connect: z.lazy(() => SignatureWhereUniqueInputSchema).optional()
}).strict();

export const SignatureFieldUncheckedCreateNestedManyWithoutSignerInputSchema: z.ZodType<Prisma.SignatureFieldUncheckedCreateNestedManyWithoutSignerInput> = z.object({
  create: z.union([ z.lazy(() => SignatureFieldCreateWithoutSignerInputSchema),z.lazy(() => SignatureFieldCreateWithoutSignerInputSchema).array(),z.lazy(() => SignatureFieldUncheckedCreateWithoutSignerInputSchema),z.lazy(() => SignatureFieldUncheckedCreateWithoutSignerInputSchema).array() ]).optional(),
  connectOrCreate: z.union([ z.lazy(() => SignatureFieldCreateOrConnectWithoutSignerInputSchema),z.lazy(() => SignatureFieldCreateOrConnectWithoutSignerInputSchema).array() ]).optional(),
  createMany: z.lazy(() => SignatureFieldCreateManySignerInputEnvelopeSchema).optional(),
  connect: z.union([ z.lazy(() => SignatureFieldWhereUniqueInputSchema),z.lazy(() => SignatureFieldWhereUniqueInputSchema).array() ]).optional(),
}).strict();

export const EnumSignerStatusFieldUpdateOperationsInputSchema: z.ZodType<Prisma.EnumSignerStatusFieldUpdateOperationsInput> = z.object({
  set: z.lazy(() => SignerStatusSchema).optional()
}).strict();

export const DocumentUpdateOneRequiredWithoutSignersNestedInputSchema: z.ZodType<Prisma.DocumentUpdateOneRequiredWithoutSignersNestedInput> = z.object({
  create: z.union([ z.lazy(() => DocumentCreateWithoutSignersInputSchema),z.lazy(() => DocumentUncheckedCreateWithoutSignersInputSchema) ]).optional(),
  connectOrCreate: z.lazy(() => DocumentCreateOrConnectWithoutSignersInputSchema).optional(),
  upsert: z.lazy(() => DocumentUpsertWithoutSignersInputSchema).optional(),
  connect: z.lazy(() => DocumentWhereUniqueInputSchema).optional(),
  update: z.union([ z.lazy(() => DocumentUpdateToOneWithWhereWithoutSignersInputSchema),z.lazy(() => DocumentUpdateWithoutSignersInputSchema),z.lazy(() => DocumentUncheckedUpdateWithoutSignersInputSchema) ]).optional(),
}).strict();

export const SignatureFieldUpdateManyWithoutSignerNestedInputSchema: z.ZodType<Prisma.SignatureFieldUpdateManyWithoutSignerNestedInput> = z.object({
  create: z.union([ z.lazy(() => SignatureFieldCreateWithoutSignerInputSchema),z.lazy(() => SignatureFieldCreateWithoutSignerInputSchema).array(),z.lazy(() => SignatureFieldUncheckedCreateWithoutSignerInputSchema),z.lazy(() => SignatureFieldUncheckedCreateWithoutSignerInputSchema).array() ]).optional(),
  connectOrCreate: z.union([ z.lazy(() => SignatureFieldCreateOrConnectWithoutSignerInputSchema),z.lazy(() => SignatureFieldCreateOrConnectWithoutSignerInputSchema).array() ]).optional(),
  upsert: z.union([ z.lazy(() => SignatureFieldUpsertWithWhereUniqueWithoutSignerInputSchema),z.lazy(() => SignatureFieldUpsertWithWhereUniqueWithoutSignerInputSchema).array() ]).optional(),
  createMany: z.lazy(() => SignatureFieldCreateManySignerInputEnvelopeSchema).optional(),
  set: z.union([ z.lazy(() => SignatureFieldWhereUniqueInputSchema),z.lazy(() => SignatureFieldWhereUniqueInputSchema).array() ]).optional(),
  disconnect: z.union([ z.lazy(() => SignatureFieldWhereUniqueInputSchema),z.lazy(() => SignatureFieldWhereUniqueInputSchema).array() ]).optional(),
  delete: z.union([ z.lazy(() => SignatureFieldWhereUniqueInputSchema),z.lazy(() => SignatureFieldWhereUniqueInputSchema).array() ]).optional(),
  connect: z.union([ z.lazy(() => SignatureFieldWhereUniqueInputSchema),z.lazy(() => SignatureFieldWhereUniqueInputSchema).array() ]).optional(),
  update: z.union([ z.lazy(() => SignatureFieldUpdateWithWhereUniqueWithoutSignerInputSchema),z.lazy(() => SignatureFieldUpdateWithWhereUniqueWithoutSignerInputSchema).array() ]).optional(),
  updateMany: z.union([ z.lazy(() => SignatureFieldUpdateManyWithWhereWithoutSignerInputSchema),z.lazy(() => SignatureFieldUpdateManyWithWhereWithoutSignerInputSchema).array() ]).optional(),
  deleteMany: z.union([ z.lazy(() => SignatureFieldScalarWhereInputSchema),z.lazy(() => SignatureFieldScalarWhereInputSchema).array() ]).optional(),
}).strict();

export const SignatureUpdateOneWithoutDocumentSignerNestedInputSchema: z.ZodType<Prisma.SignatureUpdateOneWithoutDocumentSignerNestedInput> = z.object({
  create: z.union([ z.lazy(() => SignatureCreateWithoutDocumentSignerInputSchema),z.lazy(() => SignatureUncheckedCreateWithoutDocumentSignerInputSchema) ]).optional(),
  connectOrCreate: z.lazy(() => SignatureCreateOrConnectWithoutDocumentSignerInputSchema).optional(),
  upsert: z.lazy(() => SignatureUpsertWithoutDocumentSignerInputSchema).optional(),
  disconnect: z.union([ z.boolean(),z.lazy(() => SignatureWhereInputSchema) ]).optional(),
  delete: z.union([ z.boolean(),z.lazy(() => SignatureWhereInputSchema) ]).optional(),
  connect: z.lazy(() => SignatureWhereUniqueInputSchema).optional(),
  update: z.union([ z.lazy(() => SignatureUpdateToOneWithWhereWithoutDocumentSignerInputSchema),z.lazy(() => SignatureUpdateWithoutDocumentSignerInputSchema),z.lazy(() => SignatureUncheckedUpdateWithoutDocumentSignerInputSchema) ]).optional(),
}).strict();

export const SignatureFieldUncheckedUpdateManyWithoutSignerNestedInputSchema: z.ZodType<Prisma.SignatureFieldUncheckedUpdateManyWithoutSignerNestedInput> = z.object({
  create: z.union([ z.lazy(() => SignatureFieldCreateWithoutSignerInputSchema),z.lazy(() => SignatureFieldCreateWithoutSignerInputSchema).array(),z.lazy(() => SignatureFieldUncheckedCreateWithoutSignerInputSchema),z.lazy(() => SignatureFieldUncheckedCreateWithoutSignerInputSchema).array() ]).optional(),
  connectOrCreate: z.union([ z.lazy(() => SignatureFieldCreateOrConnectWithoutSignerInputSchema),z.lazy(() => SignatureFieldCreateOrConnectWithoutSignerInputSchema).array() ]).optional(),
  upsert: z.union([ z.lazy(() => SignatureFieldUpsertWithWhereUniqueWithoutSignerInputSchema),z.lazy(() => SignatureFieldUpsertWithWhereUniqueWithoutSignerInputSchema).array() ]).optional(),
  createMany: z.lazy(() => SignatureFieldCreateManySignerInputEnvelopeSchema).optional(),
  set: z.union([ z.lazy(() => SignatureFieldWhereUniqueInputSchema),z.lazy(() => SignatureFieldWhereUniqueInputSchema).array() ]).optional(),
  disconnect: z.union([ z.lazy(() => SignatureFieldWhereUniqueInputSchema),z.lazy(() => SignatureFieldWhereUniqueInputSchema).array() ]).optional(),
  delete: z.union([ z.lazy(() => SignatureFieldWhereUniqueInputSchema),z.lazy(() => SignatureFieldWhereUniqueInputSchema).array() ]).optional(),
  connect: z.union([ z.lazy(() => SignatureFieldWhereUniqueInputSchema),z.lazy(() => SignatureFieldWhereUniqueInputSchema).array() ]).optional(),
  update: z.union([ z.lazy(() => SignatureFieldUpdateWithWhereUniqueWithoutSignerInputSchema),z.lazy(() => SignatureFieldUpdateWithWhereUniqueWithoutSignerInputSchema).array() ]).optional(),
  updateMany: z.union([ z.lazy(() => SignatureFieldUpdateManyWithWhereWithoutSignerInputSchema),z.lazy(() => SignatureFieldUpdateManyWithWhereWithoutSignerInputSchema).array() ]).optional(),
  deleteMany: z.union([ z.lazy(() => SignatureFieldScalarWhereInputSchema),z.lazy(() => SignatureFieldScalarWhereInputSchema).array() ]).optional(),
}).strict();

export const DocumentCreateNestedOneWithoutSignatureFieldInputSchema: z.ZodType<Prisma.DocumentCreateNestedOneWithoutSignatureFieldInput> = z.object({
  create: z.union([ z.lazy(() => DocumentCreateWithoutSignatureFieldInputSchema),z.lazy(() => DocumentUncheckedCreateWithoutSignatureFieldInputSchema) ]).optional(),
  connectOrCreate: z.lazy(() => DocumentCreateOrConnectWithoutSignatureFieldInputSchema).optional(),
  connect: z.lazy(() => DocumentWhereUniqueInputSchema).optional()
}).strict();

export const DocumentSignerCreateNestedOneWithoutSignatureFieldsInputSchema: z.ZodType<Prisma.DocumentSignerCreateNestedOneWithoutSignatureFieldsInput> = z.object({
  create: z.union([ z.lazy(() => DocumentSignerCreateWithoutSignatureFieldsInputSchema),z.lazy(() => DocumentSignerUncheckedCreateWithoutSignatureFieldsInputSchema) ]).optional(),
  connectOrCreate: z.lazy(() => DocumentSignerCreateOrConnectWithoutSignatureFieldsInputSchema).optional(),
  connect: z.lazy(() => DocumentSignerWhereUniqueInputSchema).optional()
}).strict();

export const EnumFieldTypeFieldUpdateOperationsInputSchema: z.ZodType<Prisma.EnumFieldTypeFieldUpdateOperationsInput> = z.object({
  set: z.lazy(() => FieldTypeSchema).optional()
}).strict();

export const BoolFieldUpdateOperationsInputSchema: z.ZodType<Prisma.BoolFieldUpdateOperationsInput> = z.object({
  set: z.boolean().optional()
}).strict();

export const FloatFieldUpdateOperationsInputSchema: z.ZodType<Prisma.FloatFieldUpdateOperationsInput> = z.object({
  set: z.number().optional(),
  increment: z.number().optional(),
  decrement: z.number().optional(),
  multiply: z.number().optional(),
  divide: z.number().optional()
}).strict();

export const DocumentUpdateOneRequiredWithoutSignatureFieldNestedInputSchema: z.ZodType<Prisma.DocumentUpdateOneRequiredWithoutSignatureFieldNestedInput> = z.object({
  create: z.union([ z.lazy(() => DocumentCreateWithoutSignatureFieldInputSchema),z.lazy(() => DocumentUncheckedCreateWithoutSignatureFieldInputSchema) ]).optional(),
  connectOrCreate: z.lazy(() => DocumentCreateOrConnectWithoutSignatureFieldInputSchema).optional(),
  upsert: z.lazy(() => DocumentUpsertWithoutSignatureFieldInputSchema).optional(),
  connect: z.lazy(() => DocumentWhereUniqueInputSchema).optional(),
  update: z.union([ z.lazy(() => DocumentUpdateToOneWithWhereWithoutSignatureFieldInputSchema),z.lazy(() => DocumentUpdateWithoutSignatureFieldInputSchema),z.lazy(() => DocumentUncheckedUpdateWithoutSignatureFieldInputSchema) ]).optional(),
}).strict();

export const DocumentSignerUpdateOneRequiredWithoutSignatureFieldsNestedInputSchema: z.ZodType<Prisma.DocumentSignerUpdateOneRequiredWithoutSignatureFieldsNestedInput> = z.object({
  create: z.union([ z.lazy(() => DocumentSignerCreateWithoutSignatureFieldsInputSchema),z.lazy(() => DocumentSignerUncheckedCreateWithoutSignatureFieldsInputSchema) ]).optional(),
  connectOrCreate: z.lazy(() => DocumentSignerCreateOrConnectWithoutSignatureFieldsInputSchema).optional(),
  upsert: z.lazy(() => DocumentSignerUpsertWithoutSignatureFieldsInputSchema).optional(),
  connect: z.lazy(() => DocumentSignerWhereUniqueInputSchema).optional(),
  update: z.union([ z.lazy(() => DocumentSignerUpdateToOneWithWhereWithoutSignatureFieldsInputSchema),z.lazy(() => DocumentSignerUpdateWithoutSignatureFieldsInputSchema),z.lazy(() => DocumentSignerUncheckedUpdateWithoutSignatureFieldsInputSchema) ]).optional(),
}).strict();

export const DocumentCreateNestedOneWithoutSignaturesInputSchema: z.ZodType<Prisma.DocumentCreateNestedOneWithoutSignaturesInput> = z.object({
  create: z.union([ z.lazy(() => DocumentCreateWithoutSignaturesInputSchema),z.lazy(() => DocumentUncheckedCreateWithoutSignaturesInputSchema) ]).optional(),
  connectOrCreate: z.lazy(() => DocumentCreateOrConnectWithoutSignaturesInputSchema).optional(),
  connect: z.lazy(() => DocumentWhereUniqueInputSchema).optional()
}).strict();

export const UserCreateNestedOneWithoutSignaturesInputSchema: z.ZodType<Prisma.UserCreateNestedOneWithoutSignaturesInput> = z.object({
  create: z.union([ z.lazy(() => UserCreateWithoutSignaturesInputSchema),z.lazy(() => UserUncheckedCreateWithoutSignaturesInputSchema) ]).optional(),
  connectOrCreate: z.lazy(() => UserCreateOrConnectWithoutSignaturesInputSchema).optional(),
  connect: z.lazy(() => UserWhereUniqueInputSchema).optional()
}).strict();

export const CertificateCreateNestedOneWithoutSignaturesInputSchema: z.ZodType<Prisma.CertificateCreateNestedOneWithoutSignaturesInput> = z.object({
  create: z.union([ z.lazy(() => CertificateCreateWithoutSignaturesInputSchema),z.lazy(() => CertificateUncheckedCreateWithoutSignaturesInputSchema) ]).optional(),
  connectOrCreate: z.lazy(() => CertificateCreateOrConnectWithoutSignaturesInputSchema).optional(),
  connect: z.lazy(() => CertificateWhereUniqueInputSchema).optional()
}).strict();

export const DocumentSignerCreateNestedManyWithoutSignatureInputSchema: z.ZodType<Prisma.DocumentSignerCreateNestedManyWithoutSignatureInput> = z.object({
  create: z.union([ z.lazy(() => DocumentSignerCreateWithoutSignatureInputSchema),z.lazy(() => DocumentSignerCreateWithoutSignatureInputSchema).array(),z.lazy(() => DocumentSignerUncheckedCreateWithoutSignatureInputSchema),z.lazy(() => DocumentSignerUncheckedCreateWithoutSignatureInputSchema).array() ]).optional(),
  connectOrCreate: z.union([ z.lazy(() => DocumentSignerCreateOrConnectWithoutSignatureInputSchema),z.lazy(() => DocumentSignerCreateOrConnectWithoutSignatureInputSchema).array() ]).optional(),
  createMany: z.lazy(() => DocumentSignerCreateManySignatureInputEnvelopeSchema).optional(),
  connect: z.union([ z.lazy(() => DocumentSignerWhereUniqueInputSchema),z.lazy(() => DocumentSignerWhereUniqueInputSchema).array() ]).optional(),
}).strict();

export const DocumentSignerUncheckedCreateNestedManyWithoutSignatureInputSchema: z.ZodType<Prisma.DocumentSignerUncheckedCreateNestedManyWithoutSignatureInput> = z.object({
  create: z.union([ z.lazy(() => DocumentSignerCreateWithoutSignatureInputSchema),z.lazy(() => DocumentSignerCreateWithoutSignatureInputSchema).array(),z.lazy(() => DocumentSignerUncheckedCreateWithoutSignatureInputSchema),z.lazy(() => DocumentSignerUncheckedCreateWithoutSignatureInputSchema).array() ]).optional(),
  connectOrCreate: z.union([ z.lazy(() => DocumentSignerCreateOrConnectWithoutSignatureInputSchema),z.lazy(() => DocumentSignerCreateOrConnectWithoutSignatureInputSchema).array() ]).optional(),
  createMany: z.lazy(() => DocumentSignerCreateManySignatureInputEnvelopeSchema).optional(),
  connect: z.union([ z.lazy(() => DocumentSignerWhereUniqueInputSchema),z.lazy(() => DocumentSignerWhereUniqueInputSchema).array() ]).optional(),
}).strict();

export const DocumentUpdateOneRequiredWithoutSignaturesNestedInputSchema: z.ZodType<Prisma.DocumentUpdateOneRequiredWithoutSignaturesNestedInput> = z.object({
  create: z.union([ z.lazy(() => DocumentCreateWithoutSignaturesInputSchema),z.lazy(() => DocumentUncheckedCreateWithoutSignaturesInputSchema) ]).optional(),
  connectOrCreate: z.lazy(() => DocumentCreateOrConnectWithoutSignaturesInputSchema).optional(),
  upsert: z.lazy(() => DocumentUpsertWithoutSignaturesInputSchema).optional(),
  connect: z.lazy(() => DocumentWhereUniqueInputSchema).optional(),
  update: z.union([ z.lazy(() => DocumentUpdateToOneWithWhereWithoutSignaturesInputSchema),z.lazy(() => DocumentUpdateWithoutSignaturesInputSchema),z.lazy(() => DocumentUncheckedUpdateWithoutSignaturesInputSchema) ]).optional(),
}).strict();

export const UserUpdateOneRequiredWithoutSignaturesNestedInputSchema: z.ZodType<Prisma.UserUpdateOneRequiredWithoutSignaturesNestedInput> = z.object({
  create: z.union([ z.lazy(() => UserCreateWithoutSignaturesInputSchema),z.lazy(() => UserUncheckedCreateWithoutSignaturesInputSchema) ]).optional(),
  connectOrCreate: z.lazy(() => UserCreateOrConnectWithoutSignaturesInputSchema).optional(),
  upsert: z.lazy(() => UserUpsertWithoutSignaturesInputSchema).optional(),
  connect: z.lazy(() => UserWhereUniqueInputSchema).optional(),
  update: z.union([ z.lazy(() => UserUpdateToOneWithWhereWithoutSignaturesInputSchema),z.lazy(() => UserUpdateWithoutSignaturesInputSchema),z.lazy(() => UserUncheckedUpdateWithoutSignaturesInputSchema) ]).optional(),
}).strict();

export const CertificateUpdateOneRequiredWithoutSignaturesNestedInputSchema: z.ZodType<Prisma.CertificateUpdateOneRequiredWithoutSignaturesNestedInput> = z.object({
  create: z.union([ z.lazy(() => CertificateCreateWithoutSignaturesInputSchema),z.lazy(() => CertificateUncheckedCreateWithoutSignaturesInputSchema) ]).optional(),
  connectOrCreate: z.lazy(() => CertificateCreateOrConnectWithoutSignaturesInputSchema).optional(),
  upsert: z.lazy(() => CertificateUpsertWithoutSignaturesInputSchema).optional(),
  connect: z.lazy(() => CertificateWhereUniqueInputSchema).optional(),
  update: z.union([ z.lazy(() => CertificateUpdateToOneWithWhereWithoutSignaturesInputSchema),z.lazy(() => CertificateUpdateWithoutSignaturesInputSchema),z.lazy(() => CertificateUncheckedUpdateWithoutSignaturesInputSchema) ]).optional(),
}).strict();

export const DocumentSignerUpdateManyWithoutSignatureNestedInputSchema: z.ZodType<Prisma.DocumentSignerUpdateManyWithoutSignatureNestedInput> = z.object({
  create: z.union([ z.lazy(() => DocumentSignerCreateWithoutSignatureInputSchema),z.lazy(() => DocumentSignerCreateWithoutSignatureInputSchema).array(),z.lazy(() => DocumentSignerUncheckedCreateWithoutSignatureInputSchema),z.lazy(() => DocumentSignerUncheckedCreateWithoutSignatureInputSchema).array() ]).optional(),
  connectOrCreate: z.union([ z.lazy(() => DocumentSignerCreateOrConnectWithoutSignatureInputSchema),z.lazy(() => DocumentSignerCreateOrConnectWithoutSignatureInputSchema).array() ]).optional(),
  upsert: z.union([ z.lazy(() => DocumentSignerUpsertWithWhereUniqueWithoutSignatureInputSchema),z.lazy(() => DocumentSignerUpsertWithWhereUniqueWithoutSignatureInputSchema).array() ]).optional(),
  createMany: z.lazy(() => DocumentSignerCreateManySignatureInputEnvelopeSchema).optional(),
  set: z.union([ z.lazy(() => DocumentSignerWhereUniqueInputSchema),z.lazy(() => DocumentSignerWhereUniqueInputSchema).array() ]).optional(),
  disconnect: z.union([ z.lazy(() => DocumentSignerWhereUniqueInputSchema),z.lazy(() => DocumentSignerWhereUniqueInputSchema).array() ]).optional(),
  delete: z.union([ z.lazy(() => DocumentSignerWhereUniqueInputSchema),z.lazy(() => DocumentSignerWhereUniqueInputSchema).array() ]).optional(),
  connect: z.union([ z.lazy(() => DocumentSignerWhereUniqueInputSchema),z.lazy(() => DocumentSignerWhereUniqueInputSchema).array() ]).optional(),
  update: z.union([ z.lazy(() => DocumentSignerUpdateWithWhereUniqueWithoutSignatureInputSchema),z.lazy(() => DocumentSignerUpdateWithWhereUniqueWithoutSignatureInputSchema).array() ]).optional(),
  updateMany: z.union([ z.lazy(() => DocumentSignerUpdateManyWithWhereWithoutSignatureInputSchema),z.lazy(() => DocumentSignerUpdateManyWithWhereWithoutSignatureInputSchema).array() ]).optional(),
  deleteMany: z.union([ z.lazy(() => DocumentSignerScalarWhereInputSchema),z.lazy(() => DocumentSignerScalarWhereInputSchema).array() ]).optional(),
}).strict();

export const DocumentSignerUncheckedUpdateManyWithoutSignatureNestedInputSchema: z.ZodType<Prisma.DocumentSignerUncheckedUpdateManyWithoutSignatureNestedInput> = z.object({
  create: z.union([ z.lazy(() => DocumentSignerCreateWithoutSignatureInputSchema),z.lazy(() => DocumentSignerCreateWithoutSignatureInputSchema).array(),z.lazy(() => DocumentSignerUncheckedCreateWithoutSignatureInputSchema),z.lazy(() => DocumentSignerUncheckedCreateWithoutSignatureInputSchema).array() ]).optional(),
  connectOrCreate: z.union([ z.lazy(() => DocumentSignerCreateOrConnectWithoutSignatureInputSchema),z.lazy(() => DocumentSignerCreateOrConnectWithoutSignatureInputSchema).array() ]).optional(),
  upsert: z.union([ z.lazy(() => DocumentSignerUpsertWithWhereUniqueWithoutSignatureInputSchema),z.lazy(() => DocumentSignerUpsertWithWhereUniqueWithoutSignatureInputSchema).array() ]).optional(),
  createMany: z.lazy(() => DocumentSignerCreateManySignatureInputEnvelopeSchema).optional(),
  set: z.union([ z.lazy(() => DocumentSignerWhereUniqueInputSchema),z.lazy(() => DocumentSignerWhereUniqueInputSchema).array() ]).optional(),
  disconnect: z.union([ z.lazy(() => DocumentSignerWhereUniqueInputSchema),z.lazy(() => DocumentSignerWhereUniqueInputSchema).array() ]).optional(),
  delete: z.union([ z.lazy(() => DocumentSignerWhereUniqueInputSchema),z.lazy(() => DocumentSignerWhereUniqueInputSchema).array() ]).optional(),
  connect: z.union([ z.lazy(() => DocumentSignerWhereUniqueInputSchema),z.lazy(() => DocumentSignerWhereUniqueInputSchema).array() ]).optional(),
  update: z.union([ z.lazy(() => DocumentSignerUpdateWithWhereUniqueWithoutSignatureInputSchema),z.lazy(() => DocumentSignerUpdateWithWhereUniqueWithoutSignatureInputSchema).array() ]).optional(),
  updateMany: z.union([ z.lazy(() => DocumentSignerUpdateManyWithWhereWithoutSignatureInputSchema),z.lazy(() => DocumentSignerUpdateManyWithWhereWithoutSignatureInputSchema).array() ]).optional(),
  deleteMany: z.union([ z.lazy(() => DocumentSignerScalarWhereInputSchema),z.lazy(() => DocumentSignerScalarWhereInputSchema).array() ]).optional(),
}).strict();

export const CompanyCreateNestedOneWithoutCertificatesInputSchema: z.ZodType<Prisma.CompanyCreateNestedOneWithoutCertificatesInput> = z.object({
  create: z.union([ z.lazy(() => CompanyCreateWithoutCertificatesInputSchema),z.lazy(() => CompanyUncheckedCreateWithoutCertificatesInputSchema) ]).optional(),
  connectOrCreate: z.lazy(() => CompanyCreateOrConnectWithoutCertificatesInputSchema).optional(),
  connect: z.lazy(() => CompanyWhereUniqueInputSchema).optional()
}).strict();

export const SignatureCreateNestedManyWithoutCertificateInputSchema: z.ZodType<Prisma.SignatureCreateNestedManyWithoutCertificateInput> = z.object({
  create: z.union([ z.lazy(() => SignatureCreateWithoutCertificateInputSchema),z.lazy(() => SignatureCreateWithoutCertificateInputSchema).array(),z.lazy(() => SignatureUncheckedCreateWithoutCertificateInputSchema),z.lazy(() => SignatureUncheckedCreateWithoutCertificateInputSchema).array() ]).optional(),
  connectOrCreate: z.union([ z.lazy(() => SignatureCreateOrConnectWithoutCertificateInputSchema),z.lazy(() => SignatureCreateOrConnectWithoutCertificateInputSchema).array() ]).optional(),
  createMany: z.lazy(() => SignatureCreateManyCertificateInputEnvelopeSchema).optional(),
  connect: z.union([ z.lazy(() => SignatureWhereUniqueInputSchema),z.lazy(() => SignatureWhereUniqueInputSchema).array() ]).optional(),
}).strict();

export const SignatureUncheckedCreateNestedManyWithoutCertificateInputSchema: z.ZodType<Prisma.SignatureUncheckedCreateNestedManyWithoutCertificateInput> = z.object({
  create: z.union([ z.lazy(() => SignatureCreateWithoutCertificateInputSchema),z.lazy(() => SignatureCreateWithoutCertificateInputSchema).array(),z.lazy(() => SignatureUncheckedCreateWithoutCertificateInputSchema),z.lazy(() => SignatureUncheckedCreateWithoutCertificateInputSchema).array() ]).optional(),
  connectOrCreate: z.union([ z.lazy(() => SignatureCreateOrConnectWithoutCertificateInputSchema),z.lazy(() => SignatureCreateOrConnectWithoutCertificateInputSchema).array() ]).optional(),
  createMany: z.lazy(() => SignatureCreateManyCertificateInputEnvelopeSchema).optional(),
  connect: z.union([ z.lazy(() => SignatureWhereUniqueInputSchema),z.lazy(() => SignatureWhereUniqueInputSchema).array() ]).optional(),
}).strict();

export const CompanyUpdateOneRequiredWithoutCertificatesNestedInputSchema: z.ZodType<Prisma.CompanyUpdateOneRequiredWithoutCertificatesNestedInput> = z.object({
  create: z.union([ z.lazy(() => CompanyCreateWithoutCertificatesInputSchema),z.lazy(() => CompanyUncheckedCreateWithoutCertificatesInputSchema) ]).optional(),
  connectOrCreate: z.lazy(() => CompanyCreateOrConnectWithoutCertificatesInputSchema).optional(),
  upsert: z.lazy(() => CompanyUpsertWithoutCertificatesInputSchema).optional(),
  connect: z.lazy(() => CompanyWhereUniqueInputSchema).optional(),
  update: z.union([ z.lazy(() => CompanyUpdateToOneWithWhereWithoutCertificatesInputSchema),z.lazy(() => CompanyUpdateWithoutCertificatesInputSchema),z.lazy(() => CompanyUncheckedUpdateWithoutCertificatesInputSchema) ]).optional(),
}).strict();

export const SignatureUpdateManyWithoutCertificateNestedInputSchema: z.ZodType<Prisma.SignatureUpdateManyWithoutCertificateNestedInput> = z.object({
  create: z.union([ z.lazy(() => SignatureCreateWithoutCertificateInputSchema),z.lazy(() => SignatureCreateWithoutCertificateInputSchema).array(),z.lazy(() => SignatureUncheckedCreateWithoutCertificateInputSchema),z.lazy(() => SignatureUncheckedCreateWithoutCertificateInputSchema).array() ]).optional(),
  connectOrCreate: z.union([ z.lazy(() => SignatureCreateOrConnectWithoutCertificateInputSchema),z.lazy(() => SignatureCreateOrConnectWithoutCertificateInputSchema).array() ]).optional(),
  upsert: z.union([ z.lazy(() => SignatureUpsertWithWhereUniqueWithoutCertificateInputSchema),z.lazy(() => SignatureUpsertWithWhereUniqueWithoutCertificateInputSchema).array() ]).optional(),
  createMany: z.lazy(() => SignatureCreateManyCertificateInputEnvelopeSchema).optional(),
  set: z.union([ z.lazy(() => SignatureWhereUniqueInputSchema),z.lazy(() => SignatureWhereUniqueInputSchema).array() ]).optional(),
  disconnect: z.union([ z.lazy(() => SignatureWhereUniqueInputSchema),z.lazy(() => SignatureWhereUniqueInputSchema).array() ]).optional(),
  delete: z.union([ z.lazy(() => SignatureWhereUniqueInputSchema),z.lazy(() => SignatureWhereUniqueInputSchema).array() ]).optional(),
  connect: z.union([ z.lazy(() => SignatureWhereUniqueInputSchema),z.lazy(() => SignatureWhereUniqueInputSchema).array() ]).optional(),
  update: z.union([ z.lazy(() => SignatureUpdateWithWhereUniqueWithoutCertificateInputSchema),z.lazy(() => SignatureUpdateWithWhereUniqueWithoutCertificateInputSchema).array() ]).optional(),
  updateMany: z.union([ z.lazy(() => SignatureUpdateManyWithWhereWithoutCertificateInputSchema),z.lazy(() => SignatureUpdateManyWithWhereWithoutCertificateInputSchema).array() ]).optional(),
  deleteMany: z.union([ z.lazy(() => SignatureScalarWhereInputSchema),z.lazy(() => SignatureScalarWhereInputSchema).array() ]).optional(),
}).strict();

export const SignatureUncheckedUpdateManyWithoutCertificateNestedInputSchema: z.ZodType<Prisma.SignatureUncheckedUpdateManyWithoutCertificateNestedInput> = z.object({
  create: z.union([ z.lazy(() => SignatureCreateWithoutCertificateInputSchema),z.lazy(() => SignatureCreateWithoutCertificateInputSchema).array(),z.lazy(() => SignatureUncheckedCreateWithoutCertificateInputSchema),z.lazy(() => SignatureUncheckedCreateWithoutCertificateInputSchema).array() ]).optional(),
  connectOrCreate: z.union([ z.lazy(() => SignatureCreateOrConnectWithoutCertificateInputSchema),z.lazy(() => SignatureCreateOrConnectWithoutCertificateInputSchema).array() ]).optional(),
  upsert: z.union([ z.lazy(() => SignatureUpsertWithWhereUniqueWithoutCertificateInputSchema),z.lazy(() => SignatureUpsertWithWhereUniqueWithoutCertificateInputSchema).array() ]).optional(),
  createMany: z.lazy(() => SignatureCreateManyCertificateInputEnvelopeSchema).optional(),
  set: z.union([ z.lazy(() => SignatureWhereUniqueInputSchema),z.lazy(() => SignatureWhereUniqueInputSchema).array() ]).optional(),
  disconnect: z.union([ z.lazy(() => SignatureWhereUniqueInputSchema),z.lazy(() => SignatureWhereUniqueInputSchema).array() ]).optional(),
  delete: z.union([ z.lazy(() => SignatureWhereUniqueInputSchema),z.lazy(() => SignatureWhereUniqueInputSchema).array() ]).optional(),
  connect: z.union([ z.lazy(() => SignatureWhereUniqueInputSchema),z.lazy(() => SignatureWhereUniqueInputSchema).array() ]).optional(),
  update: z.union([ z.lazy(() => SignatureUpdateWithWhereUniqueWithoutCertificateInputSchema),z.lazy(() => SignatureUpdateWithWhereUniqueWithoutCertificateInputSchema).array() ]).optional(),
  updateMany: z.union([ z.lazy(() => SignatureUpdateManyWithWhereWithoutCertificateInputSchema),z.lazy(() => SignatureUpdateManyWithWhereWithoutCertificateInputSchema).array() ]).optional(),
  deleteMany: z.union([ z.lazy(() => SignatureScalarWhereInputSchema),z.lazy(() => SignatureScalarWhereInputSchema).array() ]).optional(),
}).strict();

export const CompanyCreateNestedOneWithoutSigningTemplateInputSchema: z.ZodType<Prisma.CompanyCreateNestedOneWithoutSigningTemplateInput> = z.object({
  create: z.union([ z.lazy(() => CompanyCreateWithoutSigningTemplateInputSchema),z.lazy(() => CompanyUncheckedCreateWithoutSigningTemplateInputSchema) ]).optional(),
  connectOrCreate: z.lazy(() => CompanyCreateOrConnectWithoutSigningTemplateInputSchema).optional(),
  connect: z.lazy(() => CompanyWhereUniqueInputSchema).optional()
}).strict();

export const DocumentCreateNestedManyWithoutSigningTemplateInputSchema: z.ZodType<Prisma.DocumentCreateNestedManyWithoutSigningTemplateInput> = z.object({
  create: z.union([ z.lazy(() => DocumentCreateWithoutSigningTemplateInputSchema),z.lazy(() => DocumentCreateWithoutSigningTemplateInputSchema).array(),z.lazy(() => DocumentUncheckedCreateWithoutSigningTemplateInputSchema),z.lazy(() => DocumentUncheckedCreateWithoutSigningTemplateInputSchema).array() ]).optional(),
  connectOrCreate: z.union([ z.lazy(() => DocumentCreateOrConnectWithoutSigningTemplateInputSchema),z.lazy(() => DocumentCreateOrConnectWithoutSigningTemplateInputSchema).array() ]).optional(),
  createMany: z.lazy(() => DocumentCreateManySigningTemplateInputEnvelopeSchema).optional(),
  connect: z.union([ z.lazy(() => DocumentWhereUniqueInputSchema),z.lazy(() => DocumentWhereUniqueInputSchema).array() ]).optional(),
}).strict();

export const DocumentUncheckedCreateNestedManyWithoutSigningTemplateInputSchema: z.ZodType<Prisma.DocumentUncheckedCreateNestedManyWithoutSigningTemplateInput> = z.object({
  create: z.union([ z.lazy(() => DocumentCreateWithoutSigningTemplateInputSchema),z.lazy(() => DocumentCreateWithoutSigningTemplateInputSchema).array(),z.lazy(() => DocumentUncheckedCreateWithoutSigningTemplateInputSchema),z.lazy(() => DocumentUncheckedCreateWithoutSigningTemplateInputSchema).array() ]).optional(),
  connectOrCreate: z.union([ z.lazy(() => DocumentCreateOrConnectWithoutSigningTemplateInputSchema),z.lazy(() => DocumentCreateOrConnectWithoutSigningTemplateInputSchema).array() ]).optional(),
  createMany: z.lazy(() => DocumentCreateManySigningTemplateInputEnvelopeSchema).optional(),
  connect: z.union([ z.lazy(() => DocumentWhereUniqueInputSchema),z.lazy(() => DocumentWhereUniqueInputSchema).array() ]).optional(),
}).strict();

export const CompanyUpdateOneRequiredWithoutSigningTemplateNestedInputSchema: z.ZodType<Prisma.CompanyUpdateOneRequiredWithoutSigningTemplateNestedInput> = z.object({
  create: z.union([ z.lazy(() => CompanyCreateWithoutSigningTemplateInputSchema),z.lazy(() => CompanyUncheckedCreateWithoutSigningTemplateInputSchema) ]).optional(),
  connectOrCreate: z.lazy(() => CompanyCreateOrConnectWithoutSigningTemplateInputSchema).optional(),
  upsert: z.lazy(() => CompanyUpsertWithoutSigningTemplateInputSchema).optional(),
  connect: z.lazy(() => CompanyWhereUniqueInputSchema).optional(),
  update: z.union([ z.lazy(() => CompanyUpdateToOneWithWhereWithoutSigningTemplateInputSchema),z.lazy(() => CompanyUpdateWithoutSigningTemplateInputSchema),z.lazy(() => CompanyUncheckedUpdateWithoutSigningTemplateInputSchema) ]).optional(),
}).strict();

export const DocumentUpdateManyWithoutSigningTemplateNestedInputSchema: z.ZodType<Prisma.DocumentUpdateManyWithoutSigningTemplateNestedInput> = z.object({
  create: z.union([ z.lazy(() => DocumentCreateWithoutSigningTemplateInputSchema),z.lazy(() => DocumentCreateWithoutSigningTemplateInputSchema).array(),z.lazy(() => DocumentUncheckedCreateWithoutSigningTemplateInputSchema),z.lazy(() => DocumentUncheckedCreateWithoutSigningTemplateInputSchema).array() ]).optional(),
  connectOrCreate: z.union([ z.lazy(() => DocumentCreateOrConnectWithoutSigningTemplateInputSchema),z.lazy(() => DocumentCreateOrConnectWithoutSigningTemplateInputSchema).array() ]).optional(),
  upsert: z.union([ z.lazy(() => DocumentUpsertWithWhereUniqueWithoutSigningTemplateInputSchema),z.lazy(() => DocumentUpsertWithWhereUniqueWithoutSigningTemplateInputSchema).array() ]).optional(),
  createMany: z.lazy(() => DocumentCreateManySigningTemplateInputEnvelopeSchema).optional(),
  set: z.union([ z.lazy(() => DocumentWhereUniqueInputSchema),z.lazy(() => DocumentWhereUniqueInputSchema).array() ]).optional(),
  disconnect: z.union([ z.lazy(() => DocumentWhereUniqueInputSchema),z.lazy(() => DocumentWhereUniqueInputSchema).array() ]).optional(),
  delete: z.union([ z.lazy(() => DocumentWhereUniqueInputSchema),z.lazy(() => DocumentWhereUniqueInputSchema).array() ]).optional(),
  connect: z.union([ z.lazy(() => DocumentWhereUniqueInputSchema),z.lazy(() => DocumentWhereUniqueInputSchema).array() ]).optional(),
  update: z.union([ z.lazy(() => DocumentUpdateWithWhereUniqueWithoutSigningTemplateInputSchema),z.lazy(() => DocumentUpdateWithWhereUniqueWithoutSigningTemplateInputSchema).array() ]).optional(),
  updateMany: z.union([ z.lazy(() => DocumentUpdateManyWithWhereWithoutSigningTemplateInputSchema),z.lazy(() => DocumentUpdateManyWithWhereWithoutSigningTemplateInputSchema).array() ]).optional(),
  deleteMany: z.union([ z.lazy(() => DocumentScalarWhereInputSchema),z.lazy(() => DocumentScalarWhereInputSchema).array() ]).optional(),
}).strict();

export const DocumentUncheckedUpdateManyWithoutSigningTemplateNestedInputSchema: z.ZodType<Prisma.DocumentUncheckedUpdateManyWithoutSigningTemplateNestedInput> = z.object({
  create: z.union([ z.lazy(() => DocumentCreateWithoutSigningTemplateInputSchema),z.lazy(() => DocumentCreateWithoutSigningTemplateInputSchema).array(),z.lazy(() => DocumentUncheckedCreateWithoutSigningTemplateInputSchema),z.lazy(() => DocumentUncheckedCreateWithoutSigningTemplateInputSchema).array() ]).optional(),
  connectOrCreate: z.union([ z.lazy(() => DocumentCreateOrConnectWithoutSigningTemplateInputSchema),z.lazy(() => DocumentCreateOrConnectWithoutSigningTemplateInputSchema).array() ]).optional(),
  upsert: z.union([ z.lazy(() => DocumentUpsertWithWhereUniqueWithoutSigningTemplateInputSchema),z.lazy(() => DocumentUpsertWithWhereUniqueWithoutSigningTemplateInputSchema).array() ]).optional(),
  createMany: z.lazy(() => DocumentCreateManySigningTemplateInputEnvelopeSchema).optional(),
  set: z.union([ z.lazy(() => DocumentWhereUniqueInputSchema),z.lazy(() => DocumentWhereUniqueInputSchema).array() ]).optional(),
  disconnect: z.union([ z.lazy(() => DocumentWhereUniqueInputSchema),z.lazy(() => DocumentWhereUniqueInputSchema).array() ]).optional(),
  delete: z.union([ z.lazy(() => DocumentWhereUniqueInputSchema),z.lazy(() => DocumentWhereUniqueInputSchema).array() ]).optional(),
  connect: z.union([ z.lazy(() => DocumentWhereUniqueInputSchema),z.lazy(() => DocumentWhereUniqueInputSchema).array() ]).optional(),
  update: z.union([ z.lazy(() => DocumentUpdateWithWhereUniqueWithoutSigningTemplateInputSchema),z.lazy(() => DocumentUpdateWithWhereUniqueWithoutSigningTemplateInputSchema).array() ]).optional(),
  updateMany: z.union([ z.lazy(() => DocumentUpdateManyWithWhereWithoutSigningTemplateInputSchema),z.lazy(() => DocumentUpdateManyWithWhereWithoutSigningTemplateInputSchema).array() ]).optional(),
  deleteMany: z.union([ z.lazy(() => DocumentScalarWhereInputSchema),z.lazy(() => DocumentScalarWhereInputSchema).array() ]).optional(),
}).strict();

export const CompanyCreateNestedOneWithoutBlockchainWalletInputSchema: z.ZodType<Prisma.CompanyCreateNestedOneWithoutBlockchainWalletInput> = z.object({
  create: z.union([ z.lazy(() => CompanyCreateWithoutBlockchainWalletInputSchema),z.lazy(() => CompanyUncheckedCreateWithoutBlockchainWalletInputSchema) ]).optional(),
  connectOrCreate: z.lazy(() => CompanyCreateOrConnectWithoutBlockchainWalletInputSchema).optional(),
  connect: z.lazy(() => CompanyWhereUniqueInputSchema).optional()
}).strict();

export const CompanyUpdateOneRequiredWithoutBlockchainWalletNestedInputSchema: z.ZodType<Prisma.CompanyUpdateOneRequiredWithoutBlockchainWalletNestedInput> = z.object({
  create: z.union([ z.lazy(() => CompanyCreateWithoutBlockchainWalletInputSchema),z.lazy(() => CompanyUncheckedCreateWithoutBlockchainWalletInputSchema) ]).optional(),
  connectOrCreate: z.lazy(() => CompanyCreateOrConnectWithoutBlockchainWalletInputSchema).optional(),
  upsert: z.lazy(() => CompanyUpsertWithoutBlockchainWalletInputSchema).optional(),
  connect: z.lazy(() => CompanyWhereUniqueInputSchema).optional(),
  update: z.union([ z.lazy(() => CompanyUpdateToOneWithWhereWithoutBlockchainWalletInputSchema),z.lazy(() => CompanyUpdateWithoutBlockchainWalletInputSchema),z.lazy(() => CompanyUncheckedUpdateWithoutBlockchainWalletInputSchema) ]).optional(),
}).strict();

export const CompanyCreateNestedOneWithoutApiKeyInputSchema: z.ZodType<Prisma.CompanyCreateNestedOneWithoutApiKeyInput> = z.object({
  create: z.union([ z.lazy(() => CompanyCreateWithoutApiKeyInputSchema),z.lazy(() => CompanyUncheckedCreateWithoutApiKeyInputSchema) ]).optional(),
  connectOrCreate: z.lazy(() => CompanyCreateOrConnectWithoutApiKeyInputSchema).optional(),
  connect: z.lazy(() => CompanyWhereUniqueInputSchema).optional()
}).strict();

export const UserCreateNestedManyWithoutApiKeysInputSchema: z.ZodType<Prisma.UserCreateNestedManyWithoutApiKeysInput> = z.object({
  create: z.union([ z.lazy(() => UserCreateWithoutApiKeysInputSchema),z.lazy(() => UserCreateWithoutApiKeysInputSchema).array(),z.lazy(() => UserUncheckedCreateWithoutApiKeysInputSchema),z.lazy(() => UserUncheckedCreateWithoutApiKeysInputSchema).array() ]).optional(),
  connectOrCreate: z.union([ z.lazy(() => UserCreateOrConnectWithoutApiKeysInputSchema),z.lazy(() => UserCreateOrConnectWithoutApiKeysInputSchema).array() ]).optional(),
  connect: z.union([ z.lazy(() => UserWhereUniqueInputSchema),z.lazy(() => UserWhereUniqueInputSchema).array() ]).optional(),
}).strict();

export const UserUncheckedCreateNestedManyWithoutApiKeysInputSchema: z.ZodType<Prisma.UserUncheckedCreateNestedManyWithoutApiKeysInput> = z.object({
  create: z.union([ z.lazy(() => UserCreateWithoutApiKeysInputSchema),z.lazy(() => UserCreateWithoutApiKeysInputSchema).array(),z.lazy(() => UserUncheckedCreateWithoutApiKeysInputSchema),z.lazy(() => UserUncheckedCreateWithoutApiKeysInputSchema).array() ]).optional(),
  connectOrCreate: z.union([ z.lazy(() => UserCreateOrConnectWithoutApiKeysInputSchema),z.lazy(() => UserCreateOrConnectWithoutApiKeysInputSchema).array() ]).optional(),
  connect: z.union([ z.lazy(() => UserWhereUniqueInputSchema),z.lazy(() => UserWhereUniqueInputSchema).array() ]).optional(),
}).strict();

export const CompanyUpdateOneRequiredWithoutApiKeyNestedInputSchema: z.ZodType<Prisma.CompanyUpdateOneRequiredWithoutApiKeyNestedInput> = z.object({
  create: z.union([ z.lazy(() => CompanyCreateWithoutApiKeyInputSchema),z.lazy(() => CompanyUncheckedCreateWithoutApiKeyInputSchema) ]).optional(),
  connectOrCreate: z.lazy(() => CompanyCreateOrConnectWithoutApiKeyInputSchema).optional(),
  upsert: z.lazy(() => CompanyUpsertWithoutApiKeyInputSchema).optional(),
  connect: z.lazy(() => CompanyWhereUniqueInputSchema).optional(),
  update: z.union([ z.lazy(() => CompanyUpdateToOneWithWhereWithoutApiKeyInputSchema),z.lazy(() => CompanyUpdateWithoutApiKeyInputSchema),z.lazy(() => CompanyUncheckedUpdateWithoutApiKeyInputSchema) ]).optional(),
}).strict();

export const UserUpdateManyWithoutApiKeysNestedInputSchema: z.ZodType<Prisma.UserUpdateManyWithoutApiKeysNestedInput> = z.object({
  create: z.union([ z.lazy(() => UserCreateWithoutApiKeysInputSchema),z.lazy(() => UserCreateWithoutApiKeysInputSchema).array(),z.lazy(() => UserUncheckedCreateWithoutApiKeysInputSchema),z.lazy(() => UserUncheckedCreateWithoutApiKeysInputSchema).array() ]).optional(),
  connectOrCreate: z.union([ z.lazy(() => UserCreateOrConnectWithoutApiKeysInputSchema),z.lazy(() => UserCreateOrConnectWithoutApiKeysInputSchema).array() ]).optional(),
  upsert: z.union([ z.lazy(() => UserUpsertWithWhereUniqueWithoutApiKeysInputSchema),z.lazy(() => UserUpsertWithWhereUniqueWithoutApiKeysInputSchema).array() ]).optional(),
  set: z.union([ z.lazy(() => UserWhereUniqueInputSchema),z.lazy(() => UserWhereUniqueInputSchema).array() ]).optional(),
  disconnect: z.union([ z.lazy(() => UserWhereUniqueInputSchema),z.lazy(() => UserWhereUniqueInputSchema).array() ]).optional(),
  delete: z.union([ z.lazy(() => UserWhereUniqueInputSchema),z.lazy(() => UserWhereUniqueInputSchema).array() ]).optional(),
  connect: z.union([ z.lazy(() => UserWhereUniqueInputSchema),z.lazy(() => UserWhereUniqueInputSchema).array() ]).optional(),
  update: z.union([ z.lazy(() => UserUpdateWithWhereUniqueWithoutApiKeysInputSchema),z.lazy(() => UserUpdateWithWhereUniqueWithoutApiKeysInputSchema).array() ]).optional(),
  updateMany: z.union([ z.lazy(() => UserUpdateManyWithWhereWithoutApiKeysInputSchema),z.lazy(() => UserUpdateManyWithWhereWithoutApiKeysInputSchema).array() ]).optional(),
  deleteMany: z.union([ z.lazy(() => UserScalarWhereInputSchema),z.lazy(() => UserScalarWhereInputSchema).array() ]).optional(),
}).strict();

export const UserUncheckedUpdateManyWithoutApiKeysNestedInputSchema: z.ZodType<Prisma.UserUncheckedUpdateManyWithoutApiKeysNestedInput> = z.object({
  create: z.union([ z.lazy(() => UserCreateWithoutApiKeysInputSchema),z.lazy(() => UserCreateWithoutApiKeysInputSchema).array(),z.lazy(() => UserUncheckedCreateWithoutApiKeysInputSchema),z.lazy(() => UserUncheckedCreateWithoutApiKeysInputSchema).array() ]).optional(),
  connectOrCreate: z.union([ z.lazy(() => UserCreateOrConnectWithoutApiKeysInputSchema),z.lazy(() => UserCreateOrConnectWithoutApiKeysInputSchema).array() ]).optional(),
  upsert: z.union([ z.lazy(() => UserUpsertWithWhereUniqueWithoutApiKeysInputSchema),z.lazy(() => UserUpsertWithWhereUniqueWithoutApiKeysInputSchema).array() ]).optional(),
  set: z.union([ z.lazy(() => UserWhereUniqueInputSchema),z.lazy(() => UserWhereUniqueInputSchema).array() ]).optional(),
  disconnect: z.union([ z.lazy(() => UserWhereUniqueInputSchema),z.lazy(() => UserWhereUniqueInputSchema).array() ]).optional(),
  delete: z.union([ z.lazy(() => UserWhereUniqueInputSchema),z.lazy(() => UserWhereUniqueInputSchema).array() ]).optional(),
  connect: z.union([ z.lazy(() => UserWhereUniqueInputSchema),z.lazy(() => UserWhereUniqueInputSchema).array() ]).optional(),
  update: z.union([ z.lazy(() => UserUpdateWithWhereUniqueWithoutApiKeysInputSchema),z.lazy(() => UserUpdateWithWhereUniqueWithoutApiKeysInputSchema).array() ]).optional(),
  updateMany: z.union([ z.lazy(() => UserUpdateManyWithWhereWithoutApiKeysInputSchema),z.lazy(() => UserUpdateManyWithWhereWithoutApiKeysInputSchema).array() ]).optional(),
  deleteMany: z.union([ z.lazy(() => UserScalarWhereInputSchema),z.lazy(() => UserScalarWhereInputSchema).array() ]).optional(),
}).strict();

export const DocumentCreateNestedOneWithoutAuditLogsInputSchema: z.ZodType<Prisma.DocumentCreateNestedOneWithoutAuditLogsInput> = z.object({
  create: z.union([ z.lazy(() => DocumentCreateWithoutAuditLogsInputSchema),z.lazy(() => DocumentUncheckedCreateWithoutAuditLogsInputSchema) ]).optional(),
  connectOrCreate: z.lazy(() => DocumentCreateOrConnectWithoutAuditLogsInputSchema).optional(),
  connect: z.lazy(() => DocumentWhereUniqueInputSchema).optional()
}).strict();

export const DocumentUpdateOneRequiredWithoutAuditLogsNestedInputSchema: z.ZodType<Prisma.DocumentUpdateOneRequiredWithoutAuditLogsNestedInput> = z.object({
  create: z.union([ z.lazy(() => DocumentCreateWithoutAuditLogsInputSchema),z.lazy(() => DocumentUncheckedCreateWithoutAuditLogsInputSchema) ]).optional(),
  connectOrCreate: z.lazy(() => DocumentCreateOrConnectWithoutAuditLogsInputSchema).optional(),
  upsert: z.lazy(() => DocumentUpsertWithoutAuditLogsInputSchema).optional(),
  connect: z.lazy(() => DocumentWhereUniqueInputSchema).optional(),
  update: z.union([ z.lazy(() => DocumentUpdateToOneWithWhereWithoutAuditLogsInputSchema),z.lazy(() => DocumentUpdateWithoutAuditLogsInputSchema),z.lazy(() => DocumentUncheckedUpdateWithoutAuditLogsInputSchema) ]).optional(),
}).strict();

export const NestedStringFilterSchema: z.ZodType<Prisma.NestedStringFilter> = z.object({
  equals: z.string().optional(),
  in: z.string().array().optional(),
  notIn: z.string().array().optional(),
  lt: z.string().optional(),
  lte: z.string().optional(),
  gt: z.string().optional(),
  gte: z.string().optional(),
  contains: z.string().optional(),
  startsWith: z.string().optional(),
  endsWith: z.string().optional(),
  not: z.union([ z.string(),z.lazy(() => NestedStringFilterSchema) ]).optional(),
}).strict();

export const NestedIntFilterSchema: z.ZodType<Prisma.NestedIntFilter> = z.object({
  equals: z.number().optional(),
  in: z.number().array().optional(),
  notIn: z.number().array().optional(),
  lt: z.number().optional(),
  lte: z.number().optional(),
  gt: z.number().optional(),
  gte: z.number().optional(),
  not: z.union([ z.number(),z.lazy(() => NestedIntFilterSchema) ]).optional(),
}).strict();

export const NestedEnumUserRoleFilterSchema: z.ZodType<Prisma.NestedEnumUserRoleFilter> = z.object({
  equals: z.lazy(() => UserRoleSchema).optional(),
  in: z.lazy(() => UserRoleSchema).array().optional(),
  notIn: z.lazy(() => UserRoleSchema).array().optional(),
  not: z.union([ z.lazy(() => UserRoleSchema),z.lazy(() => NestedEnumUserRoleFilterSchema) ]).optional(),
}).strict();

export const NestedDateTimeFilterSchema: z.ZodType<Prisma.NestedDateTimeFilter> = z.object({
  equals: z.coerce.date().optional(),
  in: z.coerce.date().array().optional(),
  notIn: z.coerce.date().array().optional(),
  lt: z.coerce.date().optional(),
  lte: z.coerce.date().optional(),
  gt: z.coerce.date().optional(),
  gte: z.coerce.date().optional(),
  not: z.union([ z.coerce.date(),z.lazy(() => NestedDateTimeFilterSchema) ]).optional(),
}).strict();

export const NestedStringWithAggregatesFilterSchema: z.ZodType<Prisma.NestedStringWithAggregatesFilter> = z.object({
  equals: z.string().optional(),
  in: z.string().array().optional(),
  notIn: z.string().array().optional(),
  lt: z.string().optional(),
  lte: z.string().optional(),
  gt: z.string().optional(),
  gte: z.string().optional(),
  contains: z.string().optional(),
  startsWith: z.string().optional(),
  endsWith: z.string().optional(),
  not: z.union([ z.string(),z.lazy(() => NestedStringWithAggregatesFilterSchema) ]).optional(),
  _count: z.lazy(() => NestedIntFilterSchema).optional(),
  _min: z.lazy(() => NestedStringFilterSchema).optional(),
  _max: z.lazy(() => NestedStringFilterSchema).optional()
}).strict();

export const NestedIntWithAggregatesFilterSchema: z.ZodType<Prisma.NestedIntWithAggregatesFilter> = z.object({
  equals: z.number().optional(),
  in: z.number().array().optional(),
  notIn: z.number().array().optional(),
  lt: z.number().optional(),
  lte: z.number().optional(),
  gt: z.number().optional(),
  gte: z.number().optional(),
  not: z.union([ z.number(),z.lazy(() => NestedIntWithAggregatesFilterSchema) ]).optional(),
  _count: z.lazy(() => NestedIntFilterSchema).optional(),
  _avg: z.lazy(() => NestedFloatFilterSchema).optional(),
  _sum: z.lazy(() => NestedIntFilterSchema).optional(),
  _min: z.lazy(() => NestedIntFilterSchema).optional(),
  _max: z.lazy(() => NestedIntFilterSchema).optional()
}).strict();

export const NestedFloatFilterSchema: z.ZodType<Prisma.NestedFloatFilter> = z.object({
  equals: z.number().optional(),
  in: z.number().array().optional(),
  notIn: z.number().array().optional(),
  lt: z.number().optional(),
  lte: z.number().optional(),
  gt: z.number().optional(),
  gte: z.number().optional(),
  not: z.union([ z.number(),z.lazy(() => NestedFloatFilterSchema) ]).optional(),
}).strict();

export const NestedEnumUserRoleWithAggregatesFilterSchema: z.ZodType<Prisma.NestedEnumUserRoleWithAggregatesFilter> = z.object({
  equals: z.lazy(() => UserRoleSchema).optional(),
  in: z.lazy(() => UserRoleSchema).array().optional(),
  notIn: z.lazy(() => UserRoleSchema).array().optional(),
  not: z.union([ z.lazy(() => UserRoleSchema),z.lazy(() => NestedEnumUserRoleWithAggregatesFilterSchema) ]).optional(),
  _count: z.lazy(() => NestedIntFilterSchema).optional(),
  _min: z.lazy(() => NestedEnumUserRoleFilterSchema).optional(),
  _max: z.lazy(() => NestedEnumUserRoleFilterSchema).optional()
}).strict();

export const NestedDateTimeWithAggregatesFilterSchema: z.ZodType<Prisma.NestedDateTimeWithAggregatesFilter> = z.object({
  equals: z.coerce.date().optional(),
  in: z.coerce.date().array().optional(),
  notIn: z.coerce.date().array().optional(),
  lt: z.coerce.date().optional(),
  lte: z.coerce.date().optional(),
  gt: z.coerce.date().optional(),
  gte: z.coerce.date().optional(),
  not: z.union([ z.coerce.date(),z.lazy(() => NestedDateTimeWithAggregatesFilterSchema) ]).optional(),
  _count: z.lazy(() => NestedIntFilterSchema).optional(),
  _min: z.lazy(() => NestedDateTimeFilterSchema).optional(),
  _max: z.lazy(() => NestedDateTimeFilterSchema).optional()
}).strict();

export const NestedStringNullableFilterSchema: z.ZodType<Prisma.NestedStringNullableFilter> = z.object({
  equals: z.string().optional().nullable(),
  in: z.string().array().optional().nullable(),
  notIn: z.string().array().optional().nullable(),
  lt: z.string().optional(),
  lte: z.string().optional(),
  gt: z.string().optional(),
  gte: z.string().optional(),
  contains: z.string().optional(),
  startsWith: z.string().optional(),
  endsWith: z.string().optional(),
  not: z.union([ z.string(),z.lazy(() => NestedStringNullableFilterSchema) ]).optional().nullable(),
}).strict();

export const NestedStringNullableWithAggregatesFilterSchema: z.ZodType<Prisma.NestedStringNullableWithAggregatesFilter> = z.object({
  equals: z.string().optional().nullable(),
  in: z.string().array().optional().nullable(),
  notIn: z.string().array().optional().nullable(),
  lt: z.string().optional(),
  lte: z.string().optional(),
  gt: z.string().optional(),
  gte: z.string().optional(),
  contains: z.string().optional(),
  startsWith: z.string().optional(),
  endsWith: z.string().optional(),
  not: z.union([ z.string(),z.lazy(() => NestedStringNullableWithAggregatesFilterSchema) ]).optional().nullable(),
  _count: z.lazy(() => NestedIntNullableFilterSchema).optional(),
  _min: z.lazy(() => NestedStringNullableFilterSchema).optional(),
  _max: z.lazy(() => NestedStringNullableFilterSchema).optional()
}).strict();

export const NestedIntNullableFilterSchema: z.ZodType<Prisma.NestedIntNullableFilter> = z.object({
  equals: z.number().optional().nullable(),
  in: z.number().array().optional().nullable(),
  notIn: z.number().array().optional().nullable(),
  lt: z.number().optional(),
  lte: z.number().optional(),
  gt: z.number().optional(),
  gte: z.number().optional(),
  not: z.union([ z.number(),z.lazy(() => NestedIntNullableFilterSchema) ]).optional().nullable(),
}).strict();

export const NestedEnumDocumentStatusFilterSchema: z.ZodType<Prisma.NestedEnumDocumentStatusFilter> = z.object({
  equals: z.lazy(() => DocumentStatusSchema).optional(),
  in: z.lazy(() => DocumentStatusSchema).array().optional(),
  notIn: z.lazy(() => DocumentStatusSchema).array().optional(),
  not: z.union([ z.lazy(() => DocumentStatusSchema),z.lazy(() => NestedEnumDocumentStatusFilterSchema) ]).optional(),
}).strict();

export const NestedDateTimeNullableFilterSchema: z.ZodType<Prisma.NestedDateTimeNullableFilter> = z.object({
  equals: z.coerce.date().optional().nullable(),
  in: z.coerce.date().array().optional().nullable(),
  notIn: z.coerce.date().array().optional().nullable(),
  lt: z.coerce.date().optional(),
  lte: z.coerce.date().optional(),
  gt: z.coerce.date().optional(),
  gte: z.coerce.date().optional(),
  not: z.union([ z.coerce.date(),z.lazy(() => NestedDateTimeNullableFilterSchema) ]).optional().nullable(),
}).strict();

export const NestedEnumDocumentStatusWithAggregatesFilterSchema: z.ZodType<Prisma.NestedEnumDocumentStatusWithAggregatesFilter> = z.object({
  equals: z.lazy(() => DocumentStatusSchema).optional(),
  in: z.lazy(() => DocumentStatusSchema).array().optional(),
  notIn: z.lazy(() => DocumentStatusSchema).array().optional(),
  not: z.union([ z.lazy(() => DocumentStatusSchema),z.lazy(() => NestedEnumDocumentStatusWithAggregatesFilterSchema) ]).optional(),
  _count: z.lazy(() => NestedIntFilterSchema).optional(),
  _min: z.lazy(() => NestedEnumDocumentStatusFilterSchema).optional(),
  _max: z.lazy(() => NestedEnumDocumentStatusFilterSchema).optional()
}).strict();

export const NestedJsonNullableFilterSchema: z.ZodType<Prisma.NestedJsonNullableFilter> = z.object({
  equals: InputJsonValueSchema.optional(),
  path: z.string().array().optional(),
  string_contains: z.string().optional(),
  string_starts_with: z.string().optional(),
  string_ends_with: z.string().optional(),
  array_starts_with: InputJsonValueSchema.optional().nullable(),
  array_ends_with: InputJsonValueSchema.optional().nullable(),
  array_contains: InputJsonValueSchema.optional().nullable(),
  lt: InputJsonValueSchema.optional(),
  lte: InputJsonValueSchema.optional(),
  gt: InputJsonValueSchema.optional(),
  gte: InputJsonValueSchema.optional(),
  not: InputJsonValueSchema.optional()
}).strict();

export const NestedDateTimeNullableWithAggregatesFilterSchema: z.ZodType<Prisma.NestedDateTimeNullableWithAggregatesFilter> = z.object({
  equals: z.coerce.date().optional().nullable(),
  in: z.coerce.date().array().optional().nullable(),
  notIn: z.coerce.date().array().optional().nullable(),
  lt: z.coerce.date().optional(),
  lte: z.coerce.date().optional(),
  gt: z.coerce.date().optional(),
  gte: z.coerce.date().optional(),
  not: z.union([ z.coerce.date(),z.lazy(() => NestedDateTimeNullableWithAggregatesFilterSchema) ]).optional().nullable(),
  _count: z.lazy(() => NestedIntNullableFilterSchema).optional(),
  _min: z.lazy(() => NestedDateTimeNullableFilterSchema).optional(),
  _max: z.lazy(() => NestedDateTimeNullableFilterSchema).optional()
}).strict();

export const NestedEnumSignerStatusFilterSchema: z.ZodType<Prisma.NestedEnumSignerStatusFilter> = z.object({
  equals: z.lazy(() => SignerStatusSchema).optional(),
  in: z.lazy(() => SignerStatusSchema).array().optional(),
  notIn: z.lazy(() => SignerStatusSchema).array().optional(),
  not: z.union([ z.lazy(() => SignerStatusSchema),z.lazy(() => NestedEnumSignerStatusFilterSchema) ]).optional(),
}).strict();

export const NestedEnumSignerStatusWithAggregatesFilterSchema: z.ZodType<Prisma.NestedEnumSignerStatusWithAggregatesFilter> = z.object({
  equals: z.lazy(() => SignerStatusSchema).optional(),
  in: z.lazy(() => SignerStatusSchema).array().optional(),
  notIn: z.lazy(() => SignerStatusSchema).array().optional(),
  not: z.union([ z.lazy(() => SignerStatusSchema),z.lazy(() => NestedEnumSignerStatusWithAggregatesFilterSchema) ]).optional(),
  _count: z.lazy(() => NestedIntFilterSchema).optional(),
  _min: z.lazy(() => NestedEnumSignerStatusFilterSchema).optional(),
  _max: z.lazy(() => NestedEnumSignerStatusFilterSchema).optional()
}).strict();

export const NestedEnumFieldTypeFilterSchema: z.ZodType<Prisma.NestedEnumFieldTypeFilter> = z.object({
  equals: z.lazy(() => FieldTypeSchema).optional(),
  in: z.lazy(() => FieldTypeSchema).array().optional(),
  notIn: z.lazy(() => FieldTypeSchema).array().optional(),
  not: z.union([ z.lazy(() => FieldTypeSchema),z.lazy(() => NestedEnumFieldTypeFilterSchema) ]).optional(),
}).strict();

export const NestedBoolFilterSchema: z.ZodType<Prisma.NestedBoolFilter> = z.object({
  equals: z.boolean().optional(),
  not: z.union([ z.boolean(),z.lazy(() => NestedBoolFilterSchema) ]).optional(),
}).strict();

export const NestedEnumFieldTypeWithAggregatesFilterSchema: z.ZodType<Prisma.NestedEnumFieldTypeWithAggregatesFilter> = z.object({
  equals: z.lazy(() => FieldTypeSchema).optional(),
  in: z.lazy(() => FieldTypeSchema).array().optional(),
  notIn: z.lazy(() => FieldTypeSchema).array().optional(),
  not: z.union([ z.lazy(() => FieldTypeSchema),z.lazy(() => NestedEnumFieldTypeWithAggregatesFilterSchema) ]).optional(),
  _count: z.lazy(() => NestedIntFilterSchema).optional(),
  _min: z.lazy(() => NestedEnumFieldTypeFilterSchema).optional(),
  _max: z.lazy(() => NestedEnumFieldTypeFilterSchema).optional()
}).strict();

export const NestedBoolWithAggregatesFilterSchema: z.ZodType<Prisma.NestedBoolWithAggregatesFilter> = z.object({
  equals: z.boolean().optional(),
  not: z.union([ z.boolean(),z.lazy(() => NestedBoolWithAggregatesFilterSchema) ]).optional(),
  _count: z.lazy(() => NestedIntFilterSchema).optional(),
  _min: z.lazy(() => NestedBoolFilterSchema).optional(),
  _max: z.lazy(() => NestedBoolFilterSchema).optional()
}).strict();

export const NestedFloatWithAggregatesFilterSchema: z.ZodType<Prisma.NestedFloatWithAggregatesFilter> = z.object({
  equals: z.number().optional(),
  in: z.number().array().optional(),
  notIn: z.number().array().optional(),
  lt: z.number().optional(),
  lte: z.number().optional(),
  gt: z.number().optional(),
  gte: z.number().optional(),
  not: z.union([ z.number(),z.lazy(() => NestedFloatWithAggregatesFilterSchema) ]).optional(),
  _count: z.lazy(() => NestedIntFilterSchema).optional(),
  _avg: z.lazy(() => NestedFloatFilterSchema).optional(),
  _sum: z.lazy(() => NestedFloatFilterSchema).optional(),
  _min: z.lazy(() => NestedFloatFilterSchema).optional(),
  _max: z.lazy(() => NestedFloatFilterSchema).optional()
}).strict();

export const NestedJsonFilterSchema: z.ZodType<Prisma.NestedJsonFilter> = z.object({
  equals: InputJsonValueSchema.optional(),
  path: z.string().array().optional(),
  string_contains: z.string().optional(),
  string_starts_with: z.string().optional(),
  string_ends_with: z.string().optional(),
  array_starts_with: InputJsonValueSchema.optional().nullable(),
  array_ends_with: InputJsonValueSchema.optional().nullable(),
  array_contains: InputJsonValueSchema.optional().nullable(),
  lt: InputJsonValueSchema.optional(),
  lte: InputJsonValueSchema.optional(),
  gt: InputJsonValueSchema.optional(),
  gte: InputJsonValueSchema.optional(),
  not: InputJsonValueSchema.optional()
}).strict();

export const CompanyCreateWithoutUsersInputSchema: z.ZodType<Prisma.CompanyCreateWithoutUsersInput> = z.object({
  id: z.number().int(),
  name: z.string(),
  adminEmail: z.string(),
  country: z.string(),
  rootCertificate: z.string().optional().nullable(),
  subscriptionId: z.string().optional().nullable(),
  createdAt: z.coerce.date().optional(),
  updatedAt: z.coerce.date().optional(),
  documents: z.lazy(() => DocumentCreateNestedManyWithoutCompanyInputSchema).optional(),
  certificates: z.lazy(() => CertificateCreateNestedManyWithoutCompanyInputSchema).optional(),
  blockchainWallet: z.lazy(() => BlockchainWalletCreateNestedOneWithoutCompanyInputSchema).optional(),
  SigningTemplate: z.lazy(() => SigningTemplateCreateNestedManyWithoutCompanyInputSchema).optional(),
  ApiKey: z.lazy(() => ApiKeyCreateNestedManyWithoutCompanyInputSchema).optional()
}).strict();

export const CompanyUncheckedCreateWithoutUsersInputSchema: z.ZodType<Prisma.CompanyUncheckedCreateWithoutUsersInput> = z.object({
  id: z.number().int(),
  name: z.string(),
  adminEmail: z.string(),
  country: z.string(),
  rootCertificate: z.string().optional().nullable(),
  subscriptionId: z.string().optional().nullable(),
  createdAt: z.coerce.date().optional(),
  updatedAt: z.coerce.date().optional(),
  documents: z.lazy(() => DocumentUncheckedCreateNestedManyWithoutCompanyInputSchema).optional(),
  certificates: z.lazy(() => CertificateUncheckedCreateNestedManyWithoutCompanyInputSchema).optional(),
  blockchainWallet: z.lazy(() => BlockchainWalletUncheckedCreateNestedOneWithoutCompanyInputSchema).optional(),
  SigningTemplate: z.lazy(() => SigningTemplateUncheckedCreateNestedManyWithoutCompanyInputSchema).optional(),
  ApiKey: z.lazy(() => ApiKeyUncheckedCreateNestedManyWithoutCompanyInputSchema).optional()
}).strict();

export const CompanyCreateOrConnectWithoutUsersInputSchema: z.ZodType<Prisma.CompanyCreateOrConnectWithoutUsersInput> = z.object({
  where: z.lazy(() => CompanyWhereUniqueInputSchema),
  create: z.union([ z.lazy(() => CompanyCreateWithoutUsersInputSchema),z.lazy(() => CompanyUncheckedCreateWithoutUsersInputSchema) ]),
}).strict();

export const DocumentCreateWithoutUserInputSchema: z.ZodType<Prisma.DocumentCreateWithoutUserInput> = z.object({
  id: z.string().uuid().optional(),
  title: z.string().optional().nullable(),
  description: z.string().optional().nullable(),
  status: z.lazy(() => DocumentStatusSchema).optional(),
  fileUrl: z.string(),
  fileHash: z.string().optional().nullable(),
  blockchainDocId: z.string().optional().nullable(),
  metadata: z.union([ z.lazy(() => NullableJsonNullValueInputSchema),InputJsonValueSchema ]).optional(),
  expiresAt: z.coerce.date().optional().nullable(),
  createdAt: z.coerce.date().optional(),
  updatedAt: z.coerce.date().optional(),
  company: z.lazy(() => CompanyCreateNestedOneWithoutDocumentsInputSchema),
  signingTemplate: z.lazy(() => SigningTemplateCreateNestedOneWithoutDocumentsInputSchema).optional(),
  signers: z.lazy(() => DocumentSignerCreateNestedManyWithoutDocumentInputSchema).optional(),
  signatures: z.lazy(() => SignatureCreateNestedManyWithoutDocumentInputSchema).optional(),
  auditLogs: z.lazy(() => AuditLogCreateNestedManyWithoutDocumentInputSchema).optional(),
  SignatureField: z.lazy(() => SignatureFieldCreateNestedManyWithoutDocumentInputSchema).optional()
}).strict();

export const DocumentUncheckedCreateWithoutUserInputSchema: z.ZodType<Prisma.DocumentUncheckedCreateWithoutUserInput> = z.object({
  id: z.string().uuid().optional(),
  title: z.string().optional().nullable(),
  description: z.string().optional().nullable(),
  companyId: z.number().int(),
  status: z.lazy(() => DocumentStatusSchema).optional(),
  fileUrl: z.string(),
  fileHash: z.string().optional().nullable(),
  blockchainDocId: z.string().optional().nullable(),
  templateId: z.string().optional().nullable(),
  metadata: z.union([ z.lazy(() => NullableJsonNullValueInputSchema),InputJsonValueSchema ]).optional(),
  expiresAt: z.coerce.date().optional().nullable(),
  createdAt: z.coerce.date().optional(),
  updatedAt: z.coerce.date().optional(),
  signers: z.lazy(() => DocumentSignerUncheckedCreateNestedManyWithoutDocumentInputSchema).optional(),
  signatures: z.lazy(() => SignatureUncheckedCreateNestedManyWithoutDocumentInputSchema).optional(),
  auditLogs: z.lazy(() => AuditLogUncheckedCreateNestedManyWithoutDocumentInputSchema).optional(),
  SignatureField: z.lazy(() => SignatureFieldUncheckedCreateNestedManyWithoutDocumentInputSchema).optional()
}).strict();

export const DocumentCreateOrConnectWithoutUserInputSchema: z.ZodType<Prisma.DocumentCreateOrConnectWithoutUserInput> = z.object({
  where: z.lazy(() => DocumentWhereUniqueInputSchema),
  create: z.union([ z.lazy(() => DocumentCreateWithoutUserInputSchema),z.lazy(() => DocumentUncheckedCreateWithoutUserInputSchema) ]),
}).strict();

export const DocumentCreateManyUserInputEnvelopeSchema: z.ZodType<Prisma.DocumentCreateManyUserInputEnvelope> = z.object({
  data: z.union([ z.lazy(() => DocumentCreateManyUserInputSchema),z.lazy(() => DocumentCreateManyUserInputSchema).array() ]),
  skipDuplicates: z.boolean().optional()
}).strict();

export const SignatureCreateWithoutUserInputSchema: z.ZodType<Prisma.SignatureCreateWithoutUserInput> = z.object({
  id: z.string().uuid().optional(),
  signatureData: z.string(),
  visualSignature: z.string().optional().nullable(),
  blockchainTx: z.string().optional().nullable(),
  coordinates: z.union([ z.lazy(() => NullableJsonNullValueInputSchema),InputJsonValueSchema ]).optional(),
  metadata: z.union([ z.lazy(() => NullableJsonNullValueInputSchema),InputJsonValueSchema ]).optional(),
  createdAt: z.coerce.date().optional(),
  updatedAt: z.coerce.date().optional(),
  document: z.lazy(() => DocumentCreateNestedOneWithoutSignaturesInputSchema),
  certificate: z.lazy(() => CertificateCreateNestedOneWithoutSignaturesInputSchema),
  DocumentSigner: z.lazy(() => DocumentSignerCreateNestedManyWithoutSignatureInputSchema).optional()
}).strict();

export const SignatureUncheckedCreateWithoutUserInputSchema: z.ZodType<Prisma.SignatureUncheckedCreateWithoutUserInput> = z.object({
  id: z.string().uuid().optional(),
  documentId: z.string(),
  certificateId: z.string(),
  signatureData: z.string(),
  visualSignature: z.string().optional().nullable(),
  blockchainTx: z.string().optional().nullable(),
  coordinates: z.union([ z.lazy(() => NullableJsonNullValueInputSchema),InputJsonValueSchema ]).optional(),
  metadata: z.union([ z.lazy(() => NullableJsonNullValueInputSchema),InputJsonValueSchema ]).optional(),
  createdAt: z.coerce.date().optional(),
  updatedAt: z.coerce.date().optional(),
  DocumentSigner: z.lazy(() => DocumentSignerUncheckedCreateNestedManyWithoutSignatureInputSchema).optional()
}).strict();

export const SignatureCreateOrConnectWithoutUserInputSchema: z.ZodType<Prisma.SignatureCreateOrConnectWithoutUserInput> = z.object({
  where: z.lazy(() => SignatureWhereUniqueInputSchema),
  create: z.union([ z.lazy(() => SignatureCreateWithoutUserInputSchema),z.lazy(() => SignatureUncheckedCreateWithoutUserInputSchema) ]),
}).strict();

export const SignatureCreateManyUserInputEnvelopeSchema: z.ZodType<Prisma.SignatureCreateManyUserInputEnvelope> = z.object({
  data: z.union([ z.lazy(() => SignatureCreateManyUserInputSchema),z.lazy(() => SignatureCreateManyUserInputSchema).array() ]),
  skipDuplicates: z.boolean().optional()
}).strict();

export const ApiKeyCreateWithoutUserInputSchema: z.ZodType<Prisma.ApiKeyCreateWithoutUserInput> = z.object({
  id: z.string().uuid().optional(),
  key: z.string(),
  createdAt: z.coerce.date().optional(),
  updatedAt: z.coerce.date().optional(),
  isActive: z.boolean().optional(),
  isDeleted: z.boolean().optional(),
  isRevoked: z.boolean().optional(),
  lastUsed: z.coerce.date().optional().nullable(),
  company: z.lazy(() => CompanyCreateNestedOneWithoutApiKeyInputSchema)
}).strict();

export const ApiKeyUncheckedCreateWithoutUserInputSchema: z.ZodType<Prisma.ApiKeyUncheckedCreateWithoutUserInput> = z.object({
  id: z.string().uuid().optional(),
  companyId: z.number().int(),
  key: z.string(),
  createdAt: z.coerce.date().optional(),
  updatedAt: z.coerce.date().optional(),
  isActive: z.boolean().optional(),
  isDeleted: z.boolean().optional(),
  isRevoked: z.boolean().optional(),
  lastUsed: z.coerce.date().optional().nullable()
}).strict();

export const ApiKeyCreateOrConnectWithoutUserInputSchema: z.ZodType<Prisma.ApiKeyCreateOrConnectWithoutUserInput> = z.object({
  where: z.lazy(() => ApiKeyWhereUniqueInputSchema),
  create: z.union([ z.lazy(() => ApiKeyCreateWithoutUserInputSchema),z.lazy(() => ApiKeyUncheckedCreateWithoutUserInputSchema) ]),
}).strict();

export const CompanyUpsertWithoutUsersInputSchema: z.ZodType<Prisma.CompanyUpsertWithoutUsersInput> = z.object({
  update: z.union([ z.lazy(() => CompanyUpdateWithoutUsersInputSchema),z.lazy(() => CompanyUncheckedUpdateWithoutUsersInputSchema) ]),
  create: z.union([ z.lazy(() => CompanyCreateWithoutUsersInputSchema),z.lazy(() => CompanyUncheckedCreateWithoutUsersInputSchema) ]),
  where: z.lazy(() => CompanyWhereInputSchema).optional()
}).strict();

export const CompanyUpdateToOneWithWhereWithoutUsersInputSchema: z.ZodType<Prisma.CompanyUpdateToOneWithWhereWithoutUsersInput> = z.object({
  where: z.lazy(() => CompanyWhereInputSchema).optional(),
  data: z.union([ z.lazy(() => CompanyUpdateWithoutUsersInputSchema),z.lazy(() => CompanyUncheckedUpdateWithoutUsersInputSchema) ]),
}).strict();

export const CompanyUpdateWithoutUsersInputSchema: z.ZodType<Prisma.CompanyUpdateWithoutUsersInput> = z.object({
  id: z.union([ z.number().int(),z.lazy(() => IntFieldUpdateOperationsInputSchema) ]).optional(),
  name: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  adminEmail: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  country: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  rootCertificate: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  subscriptionId: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  createdAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  updatedAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  documents: z.lazy(() => DocumentUpdateManyWithoutCompanyNestedInputSchema).optional(),
  certificates: z.lazy(() => CertificateUpdateManyWithoutCompanyNestedInputSchema).optional(),
  blockchainWallet: z.lazy(() => BlockchainWalletUpdateOneWithoutCompanyNestedInputSchema).optional(),
  SigningTemplate: z.lazy(() => SigningTemplateUpdateManyWithoutCompanyNestedInputSchema).optional(),
  ApiKey: z.lazy(() => ApiKeyUpdateManyWithoutCompanyNestedInputSchema).optional()
}).strict();

export const CompanyUncheckedUpdateWithoutUsersInputSchema: z.ZodType<Prisma.CompanyUncheckedUpdateWithoutUsersInput> = z.object({
  id: z.union([ z.number().int(),z.lazy(() => IntFieldUpdateOperationsInputSchema) ]).optional(),
  name: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  adminEmail: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  country: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  rootCertificate: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  subscriptionId: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  createdAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  updatedAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  documents: z.lazy(() => DocumentUncheckedUpdateManyWithoutCompanyNestedInputSchema).optional(),
  certificates: z.lazy(() => CertificateUncheckedUpdateManyWithoutCompanyNestedInputSchema).optional(),
  blockchainWallet: z.lazy(() => BlockchainWalletUncheckedUpdateOneWithoutCompanyNestedInputSchema).optional(),
  SigningTemplate: z.lazy(() => SigningTemplateUncheckedUpdateManyWithoutCompanyNestedInputSchema).optional(),
  ApiKey: z.lazy(() => ApiKeyUncheckedUpdateManyWithoutCompanyNestedInputSchema).optional()
}).strict();

export const DocumentUpsertWithWhereUniqueWithoutUserInputSchema: z.ZodType<Prisma.DocumentUpsertWithWhereUniqueWithoutUserInput> = z.object({
  where: z.lazy(() => DocumentWhereUniqueInputSchema),
  update: z.union([ z.lazy(() => DocumentUpdateWithoutUserInputSchema),z.lazy(() => DocumentUncheckedUpdateWithoutUserInputSchema) ]),
  create: z.union([ z.lazy(() => DocumentCreateWithoutUserInputSchema),z.lazy(() => DocumentUncheckedCreateWithoutUserInputSchema) ]),
}).strict();

export const DocumentUpdateWithWhereUniqueWithoutUserInputSchema: z.ZodType<Prisma.DocumentUpdateWithWhereUniqueWithoutUserInput> = z.object({
  where: z.lazy(() => DocumentWhereUniqueInputSchema),
  data: z.union([ z.lazy(() => DocumentUpdateWithoutUserInputSchema),z.lazy(() => DocumentUncheckedUpdateWithoutUserInputSchema) ]),
}).strict();

export const DocumentUpdateManyWithWhereWithoutUserInputSchema: z.ZodType<Prisma.DocumentUpdateManyWithWhereWithoutUserInput> = z.object({
  where: z.lazy(() => DocumentScalarWhereInputSchema),
  data: z.union([ z.lazy(() => DocumentUpdateManyMutationInputSchema),z.lazy(() => DocumentUncheckedUpdateManyWithoutUserInputSchema) ]),
}).strict();

export const DocumentScalarWhereInputSchema: z.ZodType<Prisma.DocumentScalarWhereInput> = z.object({
  AND: z.union([ z.lazy(() => DocumentScalarWhereInputSchema),z.lazy(() => DocumentScalarWhereInputSchema).array() ]).optional(),
  OR: z.lazy(() => DocumentScalarWhereInputSchema).array().optional(),
  NOT: z.union([ z.lazy(() => DocumentScalarWhereInputSchema),z.lazy(() => DocumentScalarWhereInputSchema).array() ]).optional(),
  id: z.union([ z.lazy(() => StringFilterSchema),z.string() ]).optional(),
  title: z.union([ z.lazy(() => StringNullableFilterSchema),z.string() ]).optional().nullable(),
  description: z.union([ z.lazy(() => StringNullableFilterSchema),z.string() ]).optional().nullable(),
  userId: z.union([ z.lazy(() => StringFilterSchema),z.string() ]).optional(),
  companyId: z.union([ z.lazy(() => IntFilterSchema),z.number() ]).optional(),
  status: z.union([ z.lazy(() => EnumDocumentStatusFilterSchema),z.lazy(() => DocumentStatusSchema) ]).optional(),
  fileUrl: z.union([ z.lazy(() => StringFilterSchema),z.string() ]).optional(),
  fileHash: z.union([ z.lazy(() => StringNullableFilterSchema),z.string() ]).optional().nullable(),
  blockchainDocId: z.union([ z.lazy(() => StringNullableFilterSchema),z.string() ]).optional().nullable(),
  templateId: z.union([ z.lazy(() => StringNullableFilterSchema),z.string() ]).optional().nullable(),
  metadata: z.lazy(() => JsonNullableFilterSchema).optional(),
  expiresAt: z.union([ z.lazy(() => DateTimeNullableFilterSchema),z.coerce.date() ]).optional().nullable(),
  createdAt: z.union([ z.lazy(() => DateTimeFilterSchema),z.coerce.date() ]).optional(),
  updatedAt: z.union([ z.lazy(() => DateTimeFilterSchema),z.coerce.date() ]).optional(),
}).strict();

export const SignatureUpsertWithWhereUniqueWithoutUserInputSchema: z.ZodType<Prisma.SignatureUpsertWithWhereUniqueWithoutUserInput> = z.object({
  where: z.lazy(() => SignatureWhereUniqueInputSchema),
  update: z.union([ z.lazy(() => SignatureUpdateWithoutUserInputSchema),z.lazy(() => SignatureUncheckedUpdateWithoutUserInputSchema) ]),
  create: z.union([ z.lazy(() => SignatureCreateWithoutUserInputSchema),z.lazy(() => SignatureUncheckedCreateWithoutUserInputSchema) ]),
}).strict();

export const SignatureUpdateWithWhereUniqueWithoutUserInputSchema: z.ZodType<Prisma.SignatureUpdateWithWhereUniqueWithoutUserInput> = z.object({
  where: z.lazy(() => SignatureWhereUniqueInputSchema),
  data: z.union([ z.lazy(() => SignatureUpdateWithoutUserInputSchema),z.lazy(() => SignatureUncheckedUpdateWithoutUserInputSchema) ]),
}).strict();

export const SignatureUpdateManyWithWhereWithoutUserInputSchema: z.ZodType<Prisma.SignatureUpdateManyWithWhereWithoutUserInput> = z.object({
  where: z.lazy(() => SignatureScalarWhereInputSchema),
  data: z.union([ z.lazy(() => SignatureUpdateManyMutationInputSchema),z.lazy(() => SignatureUncheckedUpdateManyWithoutUserInputSchema) ]),
}).strict();

export const SignatureScalarWhereInputSchema: z.ZodType<Prisma.SignatureScalarWhereInput> = z.object({
  AND: z.union([ z.lazy(() => SignatureScalarWhereInputSchema),z.lazy(() => SignatureScalarWhereInputSchema).array() ]).optional(),
  OR: z.lazy(() => SignatureScalarWhereInputSchema).array().optional(),
  NOT: z.union([ z.lazy(() => SignatureScalarWhereInputSchema),z.lazy(() => SignatureScalarWhereInputSchema).array() ]).optional(),
  id: z.union([ z.lazy(() => StringFilterSchema),z.string() ]).optional(),
  documentId: z.union([ z.lazy(() => StringFilterSchema),z.string() ]).optional(),
  userId: z.union([ z.lazy(() => StringFilterSchema),z.string() ]).optional(),
  certificateId: z.union([ z.lazy(() => StringFilterSchema),z.string() ]).optional(),
  signatureData: z.union([ z.lazy(() => StringFilterSchema),z.string() ]).optional(),
  visualSignature: z.union([ z.lazy(() => StringNullableFilterSchema),z.string() ]).optional().nullable(),
  blockchainTx: z.union([ z.lazy(() => StringNullableFilterSchema),z.string() ]).optional().nullable(),
  coordinates: z.lazy(() => JsonNullableFilterSchema).optional(),
  metadata: z.lazy(() => JsonNullableFilterSchema).optional(),
  createdAt: z.union([ z.lazy(() => DateTimeFilterSchema),z.coerce.date() ]).optional(),
  updatedAt: z.union([ z.lazy(() => DateTimeFilterSchema),z.coerce.date() ]).optional(),
}).strict();

export const ApiKeyUpsertWithWhereUniqueWithoutUserInputSchema: z.ZodType<Prisma.ApiKeyUpsertWithWhereUniqueWithoutUserInput> = z.object({
  where: z.lazy(() => ApiKeyWhereUniqueInputSchema),
  update: z.union([ z.lazy(() => ApiKeyUpdateWithoutUserInputSchema),z.lazy(() => ApiKeyUncheckedUpdateWithoutUserInputSchema) ]),
  create: z.union([ z.lazy(() => ApiKeyCreateWithoutUserInputSchema),z.lazy(() => ApiKeyUncheckedCreateWithoutUserInputSchema) ]),
}).strict();

export const ApiKeyUpdateWithWhereUniqueWithoutUserInputSchema: z.ZodType<Prisma.ApiKeyUpdateWithWhereUniqueWithoutUserInput> = z.object({
  where: z.lazy(() => ApiKeyWhereUniqueInputSchema),
  data: z.union([ z.lazy(() => ApiKeyUpdateWithoutUserInputSchema),z.lazy(() => ApiKeyUncheckedUpdateWithoutUserInputSchema) ]),
}).strict();

export const ApiKeyUpdateManyWithWhereWithoutUserInputSchema: z.ZodType<Prisma.ApiKeyUpdateManyWithWhereWithoutUserInput> = z.object({
  where: z.lazy(() => ApiKeyScalarWhereInputSchema),
  data: z.union([ z.lazy(() => ApiKeyUpdateManyMutationInputSchema),z.lazy(() => ApiKeyUncheckedUpdateManyWithoutUserInputSchema) ]),
}).strict();

export const ApiKeyScalarWhereInputSchema: z.ZodType<Prisma.ApiKeyScalarWhereInput> = z.object({
  AND: z.union([ z.lazy(() => ApiKeyScalarWhereInputSchema),z.lazy(() => ApiKeyScalarWhereInputSchema).array() ]).optional(),
  OR: z.lazy(() => ApiKeyScalarWhereInputSchema).array().optional(),
  NOT: z.union([ z.lazy(() => ApiKeyScalarWhereInputSchema),z.lazy(() => ApiKeyScalarWhereInputSchema).array() ]).optional(),
  id: z.union([ z.lazy(() => StringFilterSchema),z.string() ]).optional(),
  companyId: z.union([ z.lazy(() => IntFilterSchema),z.number() ]).optional(),
  key: z.union([ z.lazy(() => StringFilterSchema),z.string() ]).optional(),
  createdAt: z.union([ z.lazy(() => DateTimeFilterSchema),z.coerce.date() ]).optional(),
  updatedAt: z.union([ z.lazy(() => DateTimeFilterSchema),z.coerce.date() ]).optional(),
  isActive: z.union([ z.lazy(() => BoolFilterSchema),z.boolean() ]).optional(),
  isDeleted: z.union([ z.lazy(() => BoolFilterSchema),z.boolean() ]).optional(),
  isRevoked: z.union([ z.lazy(() => BoolFilterSchema),z.boolean() ]).optional(),
  lastUsed: z.union([ z.lazy(() => DateTimeNullableFilterSchema),z.coerce.date() ]).optional().nullable(),
}).strict();

export const UserCreateWithoutCompanyInputSchema: z.ZodType<Prisma.UserCreateWithoutCompanyInput> = z.object({
  id: z.string().uuid().optional(),
  email: z.string(),
  name: z.string(),
  role: z.lazy(() => UserRoleSchema).optional(),
  createdAt: z.coerce.date().optional(),
  updatedAt: z.coerce.date().optional(),
  documents: z.lazy(() => DocumentCreateNestedManyWithoutUserInputSchema).optional(),
  signatures: z.lazy(() => SignatureCreateNestedManyWithoutUserInputSchema).optional(),
  apiKeys: z.lazy(() => ApiKeyCreateNestedManyWithoutUserInputSchema).optional()
}).strict();

export const UserUncheckedCreateWithoutCompanyInputSchema: z.ZodType<Prisma.UserUncheckedCreateWithoutCompanyInput> = z.object({
  id: z.string().uuid().optional(),
  email: z.string(),
  name: z.string(),
  role: z.lazy(() => UserRoleSchema).optional(),
  createdAt: z.coerce.date().optional(),
  updatedAt: z.coerce.date().optional(),
  documents: z.lazy(() => DocumentUncheckedCreateNestedManyWithoutUserInputSchema).optional(),
  signatures: z.lazy(() => SignatureUncheckedCreateNestedManyWithoutUserInputSchema).optional(),
  apiKeys: z.lazy(() => ApiKeyUncheckedCreateNestedManyWithoutUserInputSchema).optional()
}).strict();

export const UserCreateOrConnectWithoutCompanyInputSchema: z.ZodType<Prisma.UserCreateOrConnectWithoutCompanyInput> = z.object({
  where: z.lazy(() => UserWhereUniqueInputSchema),
  create: z.union([ z.lazy(() => UserCreateWithoutCompanyInputSchema),z.lazy(() => UserUncheckedCreateWithoutCompanyInputSchema) ]),
}).strict();

export const UserCreateManyCompanyInputEnvelopeSchema: z.ZodType<Prisma.UserCreateManyCompanyInputEnvelope> = z.object({
  data: z.union([ z.lazy(() => UserCreateManyCompanyInputSchema),z.lazy(() => UserCreateManyCompanyInputSchema).array() ]),
  skipDuplicates: z.boolean().optional()
}).strict();

export const DocumentCreateWithoutCompanyInputSchema: z.ZodType<Prisma.DocumentCreateWithoutCompanyInput> = z.object({
  id: z.string().uuid().optional(),
  title: z.string().optional().nullable(),
  description: z.string().optional().nullable(),
  status: z.lazy(() => DocumentStatusSchema).optional(),
  fileUrl: z.string(),
  fileHash: z.string().optional().nullable(),
  blockchainDocId: z.string().optional().nullable(),
  metadata: z.union([ z.lazy(() => NullableJsonNullValueInputSchema),InputJsonValueSchema ]).optional(),
  expiresAt: z.coerce.date().optional().nullable(),
  createdAt: z.coerce.date().optional(),
  updatedAt: z.coerce.date().optional(),
  user: z.lazy(() => UserCreateNestedOneWithoutDocumentsInputSchema),
  signingTemplate: z.lazy(() => SigningTemplateCreateNestedOneWithoutDocumentsInputSchema).optional(),
  signers: z.lazy(() => DocumentSignerCreateNestedManyWithoutDocumentInputSchema).optional(),
  signatures: z.lazy(() => SignatureCreateNestedManyWithoutDocumentInputSchema).optional(),
  auditLogs: z.lazy(() => AuditLogCreateNestedManyWithoutDocumentInputSchema).optional(),
  SignatureField: z.lazy(() => SignatureFieldCreateNestedManyWithoutDocumentInputSchema).optional()
}).strict();

export const DocumentUncheckedCreateWithoutCompanyInputSchema: z.ZodType<Prisma.DocumentUncheckedCreateWithoutCompanyInput> = z.object({
  id: z.string().uuid().optional(),
  title: z.string().optional().nullable(),
  description: z.string().optional().nullable(),
  userId: z.string(),
  status: z.lazy(() => DocumentStatusSchema).optional(),
  fileUrl: z.string(),
  fileHash: z.string().optional().nullable(),
  blockchainDocId: z.string().optional().nullable(),
  templateId: z.string().optional().nullable(),
  metadata: z.union([ z.lazy(() => NullableJsonNullValueInputSchema),InputJsonValueSchema ]).optional(),
  expiresAt: z.coerce.date().optional().nullable(),
  createdAt: z.coerce.date().optional(),
  updatedAt: z.coerce.date().optional(),
  signers: z.lazy(() => DocumentSignerUncheckedCreateNestedManyWithoutDocumentInputSchema).optional(),
  signatures: z.lazy(() => SignatureUncheckedCreateNestedManyWithoutDocumentInputSchema).optional(),
  auditLogs: z.lazy(() => AuditLogUncheckedCreateNestedManyWithoutDocumentInputSchema).optional(),
  SignatureField: z.lazy(() => SignatureFieldUncheckedCreateNestedManyWithoutDocumentInputSchema).optional()
}).strict();

export const DocumentCreateOrConnectWithoutCompanyInputSchema: z.ZodType<Prisma.DocumentCreateOrConnectWithoutCompanyInput> = z.object({
  where: z.lazy(() => DocumentWhereUniqueInputSchema),
  create: z.union([ z.lazy(() => DocumentCreateWithoutCompanyInputSchema),z.lazy(() => DocumentUncheckedCreateWithoutCompanyInputSchema) ]),
}).strict();

export const DocumentCreateManyCompanyInputEnvelopeSchema: z.ZodType<Prisma.DocumentCreateManyCompanyInputEnvelope> = z.object({
  data: z.union([ z.lazy(() => DocumentCreateManyCompanyInputSchema),z.lazy(() => DocumentCreateManyCompanyInputSchema).array() ]),
  skipDuplicates: z.boolean().optional()
}).strict();

export const CertificateCreateWithoutCompanyInputSchema: z.ZodType<Prisma.CertificateCreateWithoutCompanyInput> = z.object({
  id: z.string().uuid().optional(),
  fingerprint: z.string(),
  publicKey: z.string(),
  privateKey: z.string().optional().nullable(),
  isCA: z.boolean().optional(),
  issuerCertId: z.string().optional().nullable(),
  validFrom: z.coerce.date(),
  validTo: z.coerce.date(),
  metadata: z.union([ z.lazy(() => NullableJsonNullValueInputSchema),InputJsonValueSchema ]).optional(),
  createdAt: z.coerce.date().optional(),
  updatedAt: z.coerce.date().optional(),
  signatures: z.lazy(() => SignatureCreateNestedManyWithoutCertificateInputSchema).optional()
}).strict();

export const CertificateUncheckedCreateWithoutCompanyInputSchema: z.ZodType<Prisma.CertificateUncheckedCreateWithoutCompanyInput> = z.object({
  id: z.string().uuid().optional(),
  fingerprint: z.string(),
  publicKey: z.string(),
  privateKey: z.string().optional().nullable(),
  isCA: z.boolean().optional(),
  issuerCertId: z.string().optional().nullable(),
  validFrom: z.coerce.date(),
  validTo: z.coerce.date(),
  metadata: z.union([ z.lazy(() => NullableJsonNullValueInputSchema),InputJsonValueSchema ]).optional(),
  createdAt: z.coerce.date().optional(),
  updatedAt: z.coerce.date().optional(),
  signatures: z.lazy(() => SignatureUncheckedCreateNestedManyWithoutCertificateInputSchema).optional()
}).strict();

export const CertificateCreateOrConnectWithoutCompanyInputSchema: z.ZodType<Prisma.CertificateCreateOrConnectWithoutCompanyInput> = z.object({
  where: z.lazy(() => CertificateWhereUniqueInputSchema),
  create: z.union([ z.lazy(() => CertificateCreateWithoutCompanyInputSchema),z.lazy(() => CertificateUncheckedCreateWithoutCompanyInputSchema) ]),
}).strict();

export const CertificateCreateManyCompanyInputEnvelopeSchema: z.ZodType<Prisma.CertificateCreateManyCompanyInputEnvelope> = z.object({
  data: z.union([ z.lazy(() => CertificateCreateManyCompanyInputSchema),z.lazy(() => CertificateCreateManyCompanyInputSchema).array() ]),
  skipDuplicates: z.boolean().optional()
}).strict();

export const BlockchainWalletCreateWithoutCompanyInputSchema: z.ZodType<Prisma.BlockchainWalletCreateWithoutCompanyInput> = z.object({
  id: z.string().uuid().optional(),
  address: z.string(),
  privateKey: z.string().optional().nullable(),
  createdAt: z.coerce.date().optional(),
  updatedAt: z.coerce.date().optional()
}).strict();

export const BlockchainWalletUncheckedCreateWithoutCompanyInputSchema: z.ZodType<Prisma.BlockchainWalletUncheckedCreateWithoutCompanyInput> = z.object({
  id: z.string().uuid().optional(),
  address: z.string(),
  privateKey: z.string().optional().nullable(),
  createdAt: z.coerce.date().optional(),
  updatedAt: z.coerce.date().optional()
}).strict();

export const BlockchainWalletCreateOrConnectWithoutCompanyInputSchema: z.ZodType<Prisma.BlockchainWalletCreateOrConnectWithoutCompanyInput> = z.object({
  where: z.lazy(() => BlockchainWalletWhereUniqueInputSchema),
  create: z.union([ z.lazy(() => BlockchainWalletCreateWithoutCompanyInputSchema),z.lazy(() => BlockchainWalletUncheckedCreateWithoutCompanyInputSchema) ]),
}).strict();

export const SigningTemplateCreateWithoutCompanyInputSchema: z.ZodType<Prisma.SigningTemplateCreateWithoutCompanyInput> = z.object({
  id: z.string().uuid().optional(),
  name: z.string(),
  fields: z.union([ z.lazy(() => JsonNullValueInputSchema),InputJsonValueSchema ]),
  createdAt: z.coerce.date().optional(),
  updatedAt: z.coerce.date().optional(),
  documents: z.lazy(() => DocumentCreateNestedManyWithoutSigningTemplateInputSchema).optional()
}).strict();

export const SigningTemplateUncheckedCreateWithoutCompanyInputSchema: z.ZodType<Prisma.SigningTemplateUncheckedCreateWithoutCompanyInput> = z.object({
  id: z.string().uuid().optional(),
  name: z.string(),
  fields: z.union([ z.lazy(() => JsonNullValueInputSchema),InputJsonValueSchema ]),
  createdAt: z.coerce.date().optional(),
  updatedAt: z.coerce.date().optional(),
  documents: z.lazy(() => DocumentUncheckedCreateNestedManyWithoutSigningTemplateInputSchema).optional()
}).strict();

export const SigningTemplateCreateOrConnectWithoutCompanyInputSchema: z.ZodType<Prisma.SigningTemplateCreateOrConnectWithoutCompanyInput> = z.object({
  where: z.lazy(() => SigningTemplateWhereUniqueInputSchema),
  create: z.union([ z.lazy(() => SigningTemplateCreateWithoutCompanyInputSchema),z.lazy(() => SigningTemplateUncheckedCreateWithoutCompanyInputSchema) ]),
}).strict();

export const SigningTemplateCreateManyCompanyInputEnvelopeSchema: z.ZodType<Prisma.SigningTemplateCreateManyCompanyInputEnvelope> = z.object({
  data: z.union([ z.lazy(() => SigningTemplateCreateManyCompanyInputSchema),z.lazy(() => SigningTemplateCreateManyCompanyInputSchema).array() ]),
  skipDuplicates: z.boolean().optional()
}).strict();

export const ApiKeyCreateWithoutCompanyInputSchema: z.ZodType<Prisma.ApiKeyCreateWithoutCompanyInput> = z.object({
  id: z.string().uuid().optional(),
  key: z.string(),
  createdAt: z.coerce.date().optional(),
  updatedAt: z.coerce.date().optional(),
  isActive: z.boolean().optional(),
  isDeleted: z.boolean().optional(),
  isRevoked: z.boolean().optional(),
  lastUsed: z.coerce.date().optional().nullable(),
  user: z.lazy(() => UserCreateNestedManyWithoutApiKeysInputSchema).optional()
}).strict();

export const ApiKeyUncheckedCreateWithoutCompanyInputSchema: z.ZodType<Prisma.ApiKeyUncheckedCreateWithoutCompanyInput> = z.object({
  id: z.string().uuid().optional(),
  key: z.string(),
  createdAt: z.coerce.date().optional(),
  updatedAt: z.coerce.date().optional(),
  isActive: z.boolean().optional(),
  isDeleted: z.boolean().optional(),
  isRevoked: z.boolean().optional(),
  lastUsed: z.coerce.date().optional().nullable(),
  user: z.lazy(() => UserUncheckedCreateNestedManyWithoutApiKeysInputSchema).optional()
}).strict();

export const ApiKeyCreateOrConnectWithoutCompanyInputSchema: z.ZodType<Prisma.ApiKeyCreateOrConnectWithoutCompanyInput> = z.object({
  where: z.lazy(() => ApiKeyWhereUniqueInputSchema),
  create: z.union([ z.lazy(() => ApiKeyCreateWithoutCompanyInputSchema),z.lazy(() => ApiKeyUncheckedCreateWithoutCompanyInputSchema) ]),
}).strict();

export const ApiKeyCreateManyCompanyInputEnvelopeSchema: z.ZodType<Prisma.ApiKeyCreateManyCompanyInputEnvelope> = z.object({
  data: z.union([ z.lazy(() => ApiKeyCreateManyCompanyInputSchema),z.lazy(() => ApiKeyCreateManyCompanyInputSchema).array() ]),
  skipDuplicates: z.boolean().optional()
}).strict();

export const UserUpsertWithWhereUniqueWithoutCompanyInputSchema: z.ZodType<Prisma.UserUpsertWithWhereUniqueWithoutCompanyInput> = z.object({
  where: z.lazy(() => UserWhereUniqueInputSchema),
  update: z.union([ z.lazy(() => UserUpdateWithoutCompanyInputSchema),z.lazy(() => UserUncheckedUpdateWithoutCompanyInputSchema) ]),
  create: z.union([ z.lazy(() => UserCreateWithoutCompanyInputSchema),z.lazy(() => UserUncheckedCreateWithoutCompanyInputSchema) ]),
}).strict();

export const UserUpdateWithWhereUniqueWithoutCompanyInputSchema: z.ZodType<Prisma.UserUpdateWithWhereUniqueWithoutCompanyInput> = z.object({
  where: z.lazy(() => UserWhereUniqueInputSchema),
  data: z.union([ z.lazy(() => UserUpdateWithoutCompanyInputSchema),z.lazy(() => UserUncheckedUpdateWithoutCompanyInputSchema) ]),
}).strict();

export const UserUpdateManyWithWhereWithoutCompanyInputSchema: z.ZodType<Prisma.UserUpdateManyWithWhereWithoutCompanyInput> = z.object({
  where: z.lazy(() => UserScalarWhereInputSchema),
  data: z.union([ z.lazy(() => UserUpdateManyMutationInputSchema),z.lazy(() => UserUncheckedUpdateManyWithoutCompanyInputSchema) ]),
}).strict();

export const UserScalarWhereInputSchema: z.ZodType<Prisma.UserScalarWhereInput> = z.object({
  AND: z.union([ z.lazy(() => UserScalarWhereInputSchema),z.lazy(() => UserScalarWhereInputSchema).array() ]).optional(),
  OR: z.lazy(() => UserScalarWhereInputSchema).array().optional(),
  NOT: z.union([ z.lazy(() => UserScalarWhereInputSchema),z.lazy(() => UserScalarWhereInputSchema).array() ]).optional(),
  id: z.union([ z.lazy(() => StringFilterSchema),z.string() ]).optional(),
  email: z.union([ z.lazy(() => StringFilterSchema),z.string() ]).optional(),
  name: z.union([ z.lazy(() => StringFilterSchema),z.string() ]).optional(),
  companyId: z.union([ z.lazy(() => IntFilterSchema),z.number() ]).optional(),
  role: z.union([ z.lazy(() => EnumUserRoleFilterSchema),z.lazy(() => UserRoleSchema) ]).optional(),
  createdAt: z.union([ z.lazy(() => DateTimeFilterSchema),z.coerce.date() ]).optional(),
  updatedAt: z.union([ z.lazy(() => DateTimeFilterSchema),z.coerce.date() ]).optional(),
}).strict();

export const DocumentUpsertWithWhereUniqueWithoutCompanyInputSchema: z.ZodType<Prisma.DocumentUpsertWithWhereUniqueWithoutCompanyInput> = z.object({
  where: z.lazy(() => DocumentWhereUniqueInputSchema),
  update: z.union([ z.lazy(() => DocumentUpdateWithoutCompanyInputSchema),z.lazy(() => DocumentUncheckedUpdateWithoutCompanyInputSchema) ]),
  create: z.union([ z.lazy(() => DocumentCreateWithoutCompanyInputSchema),z.lazy(() => DocumentUncheckedCreateWithoutCompanyInputSchema) ]),
}).strict();

export const DocumentUpdateWithWhereUniqueWithoutCompanyInputSchema: z.ZodType<Prisma.DocumentUpdateWithWhereUniqueWithoutCompanyInput> = z.object({
  where: z.lazy(() => DocumentWhereUniqueInputSchema),
  data: z.union([ z.lazy(() => DocumentUpdateWithoutCompanyInputSchema),z.lazy(() => DocumentUncheckedUpdateWithoutCompanyInputSchema) ]),
}).strict();

export const DocumentUpdateManyWithWhereWithoutCompanyInputSchema: z.ZodType<Prisma.DocumentUpdateManyWithWhereWithoutCompanyInput> = z.object({
  where: z.lazy(() => DocumentScalarWhereInputSchema),
  data: z.union([ z.lazy(() => DocumentUpdateManyMutationInputSchema),z.lazy(() => DocumentUncheckedUpdateManyWithoutCompanyInputSchema) ]),
}).strict();

export const CertificateUpsertWithWhereUniqueWithoutCompanyInputSchema: z.ZodType<Prisma.CertificateUpsertWithWhereUniqueWithoutCompanyInput> = z.object({
  where: z.lazy(() => CertificateWhereUniqueInputSchema),
  update: z.union([ z.lazy(() => CertificateUpdateWithoutCompanyInputSchema),z.lazy(() => CertificateUncheckedUpdateWithoutCompanyInputSchema) ]),
  create: z.union([ z.lazy(() => CertificateCreateWithoutCompanyInputSchema),z.lazy(() => CertificateUncheckedCreateWithoutCompanyInputSchema) ]),
}).strict();

export const CertificateUpdateWithWhereUniqueWithoutCompanyInputSchema: z.ZodType<Prisma.CertificateUpdateWithWhereUniqueWithoutCompanyInput> = z.object({
  where: z.lazy(() => CertificateWhereUniqueInputSchema),
  data: z.union([ z.lazy(() => CertificateUpdateWithoutCompanyInputSchema),z.lazy(() => CertificateUncheckedUpdateWithoutCompanyInputSchema) ]),
}).strict();

export const CertificateUpdateManyWithWhereWithoutCompanyInputSchema: z.ZodType<Prisma.CertificateUpdateManyWithWhereWithoutCompanyInput> = z.object({
  where: z.lazy(() => CertificateScalarWhereInputSchema),
  data: z.union([ z.lazy(() => CertificateUpdateManyMutationInputSchema),z.lazy(() => CertificateUncheckedUpdateManyWithoutCompanyInputSchema) ]),
}).strict();

export const CertificateScalarWhereInputSchema: z.ZodType<Prisma.CertificateScalarWhereInput> = z.object({
  AND: z.union([ z.lazy(() => CertificateScalarWhereInputSchema),z.lazy(() => CertificateScalarWhereInputSchema).array() ]).optional(),
  OR: z.lazy(() => CertificateScalarWhereInputSchema).array().optional(),
  NOT: z.union([ z.lazy(() => CertificateScalarWhereInputSchema),z.lazy(() => CertificateScalarWhereInputSchema).array() ]).optional(),
  id: z.union([ z.lazy(() => StringFilterSchema),z.string() ]).optional(),
  companyId: z.union([ z.lazy(() => IntFilterSchema),z.number() ]).optional(),
  fingerprint: z.union([ z.lazy(() => StringFilterSchema),z.string() ]).optional(),
  publicKey: z.union([ z.lazy(() => StringFilterSchema),z.string() ]).optional(),
  privateKey: z.union([ z.lazy(() => StringNullableFilterSchema),z.string() ]).optional().nullable(),
  isCA: z.union([ z.lazy(() => BoolFilterSchema),z.boolean() ]).optional(),
  issuerCertId: z.union([ z.lazy(() => StringNullableFilterSchema),z.string() ]).optional().nullable(),
  validFrom: z.union([ z.lazy(() => DateTimeFilterSchema),z.coerce.date() ]).optional(),
  validTo: z.union([ z.lazy(() => DateTimeFilterSchema),z.coerce.date() ]).optional(),
  metadata: z.lazy(() => JsonNullableFilterSchema).optional(),
  createdAt: z.union([ z.lazy(() => DateTimeFilterSchema),z.coerce.date() ]).optional(),
  updatedAt: z.union([ z.lazy(() => DateTimeFilterSchema),z.coerce.date() ]).optional(),
}).strict();

export const BlockchainWalletUpsertWithoutCompanyInputSchema: z.ZodType<Prisma.BlockchainWalletUpsertWithoutCompanyInput> = z.object({
  update: z.union([ z.lazy(() => BlockchainWalletUpdateWithoutCompanyInputSchema),z.lazy(() => BlockchainWalletUncheckedUpdateWithoutCompanyInputSchema) ]),
  create: z.union([ z.lazy(() => BlockchainWalletCreateWithoutCompanyInputSchema),z.lazy(() => BlockchainWalletUncheckedCreateWithoutCompanyInputSchema) ]),
  where: z.lazy(() => BlockchainWalletWhereInputSchema).optional()
}).strict();

export const BlockchainWalletUpdateToOneWithWhereWithoutCompanyInputSchema: z.ZodType<Prisma.BlockchainWalletUpdateToOneWithWhereWithoutCompanyInput> = z.object({
  where: z.lazy(() => BlockchainWalletWhereInputSchema).optional(),
  data: z.union([ z.lazy(() => BlockchainWalletUpdateWithoutCompanyInputSchema),z.lazy(() => BlockchainWalletUncheckedUpdateWithoutCompanyInputSchema) ]),
}).strict();

export const BlockchainWalletUpdateWithoutCompanyInputSchema: z.ZodType<Prisma.BlockchainWalletUpdateWithoutCompanyInput> = z.object({
  id: z.union([ z.string().uuid(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  address: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  privateKey: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  createdAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  updatedAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
}).strict();

export const BlockchainWalletUncheckedUpdateWithoutCompanyInputSchema: z.ZodType<Prisma.BlockchainWalletUncheckedUpdateWithoutCompanyInput> = z.object({
  id: z.union([ z.string().uuid(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  address: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  privateKey: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  createdAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  updatedAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
}).strict();

export const SigningTemplateUpsertWithWhereUniqueWithoutCompanyInputSchema: z.ZodType<Prisma.SigningTemplateUpsertWithWhereUniqueWithoutCompanyInput> = z.object({
  where: z.lazy(() => SigningTemplateWhereUniqueInputSchema),
  update: z.union([ z.lazy(() => SigningTemplateUpdateWithoutCompanyInputSchema),z.lazy(() => SigningTemplateUncheckedUpdateWithoutCompanyInputSchema) ]),
  create: z.union([ z.lazy(() => SigningTemplateCreateWithoutCompanyInputSchema),z.lazy(() => SigningTemplateUncheckedCreateWithoutCompanyInputSchema) ]),
}).strict();

export const SigningTemplateUpdateWithWhereUniqueWithoutCompanyInputSchema: z.ZodType<Prisma.SigningTemplateUpdateWithWhereUniqueWithoutCompanyInput> = z.object({
  where: z.lazy(() => SigningTemplateWhereUniqueInputSchema),
  data: z.union([ z.lazy(() => SigningTemplateUpdateWithoutCompanyInputSchema),z.lazy(() => SigningTemplateUncheckedUpdateWithoutCompanyInputSchema) ]),
}).strict();

export const SigningTemplateUpdateManyWithWhereWithoutCompanyInputSchema: z.ZodType<Prisma.SigningTemplateUpdateManyWithWhereWithoutCompanyInput> = z.object({
  where: z.lazy(() => SigningTemplateScalarWhereInputSchema),
  data: z.union([ z.lazy(() => SigningTemplateUpdateManyMutationInputSchema),z.lazy(() => SigningTemplateUncheckedUpdateManyWithoutCompanyInputSchema) ]),
}).strict();

export const SigningTemplateScalarWhereInputSchema: z.ZodType<Prisma.SigningTemplateScalarWhereInput> = z.object({
  AND: z.union([ z.lazy(() => SigningTemplateScalarWhereInputSchema),z.lazy(() => SigningTemplateScalarWhereInputSchema).array() ]).optional(),
  OR: z.lazy(() => SigningTemplateScalarWhereInputSchema).array().optional(),
  NOT: z.union([ z.lazy(() => SigningTemplateScalarWhereInputSchema),z.lazy(() => SigningTemplateScalarWhereInputSchema).array() ]).optional(),
  id: z.union([ z.lazy(() => StringFilterSchema),z.string() ]).optional(),
  name: z.union([ z.lazy(() => StringFilterSchema),z.string() ]).optional(),
  companyId: z.union([ z.lazy(() => IntFilterSchema),z.number() ]).optional(),
  fields: z.lazy(() => JsonFilterSchema).optional(),
  createdAt: z.union([ z.lazy(() => DateTimeFilterSchema),z.coerce.date() ]).optional(),
  updatedAt: z.union([ z.lazy(() => DateTimeFilterSchema),z.coerce.date() ]).optional(),
}).strict();

export const ApiKeyUpsertWithWhereUniqueWithoutCompanyInputSchema: z.ZodType<Prisma.ApiKeyUpsertWithWhereUniqueWithoutCompanyInput> = z.object({
  where: z.lazy(() => ApiKeyWhereUniqueInputSchema),
  update: z.union([ z.lazy(() => ApiKeyUpdateWithoutCompanyInputSchema),z.lazy(() => ApiKeyUncheckedUpdateWithoutCompanyInputSchema) ]),
  create: z.union([ z.lazy(() => ApiKeyCreateWithoutCompanyInputSchema),z.lazy(() => ApiKeyUncheckedCreateWithoutCompanyInputSchema) ]),
}).strict();

export const ApiKeyUpdateWithWhereUniqueWithoutCompanyInputSchema: z.ZodType<Prisma.ApiKeyUpdateWithWhereUniqueWithoutCompanyInput> = z.object({
  where: z.lazy(() => ApiKeyWhereUniqueInputSchema),
  data: z.union([ z.lazy(() => ApiKeyUpdateWithoutCompanyInputSchema),z.lazy(() => ApiKeyUncheckedUpdateWithoutCompanyInputSchema) ]),
}).strict();

export const ApiKeyUpdateManyWithWhereWithoutCompanyInputSchema: z.ZodType<Prisma.ApiKeyUpdateManyWithWhereWithoutCompanyInput> = z.object({
  where: z.lazy(() => ApiKeyScalarWhereInputSchema),
  data: z.union([ z.lazy(() => ApiKeyUpdateManyMutationInputSchema),z.lazy(() => ApiKeyUncheckedUpdateManyWithoutCompanyInputSchema) ]),
}).strict();

export const UserCreateWithoutDocumentsInputSchema: z.ZodType<Prisma.UserCreateWithoutDocumentsInput> = z.object({
  id: z.string().uuid().optional(),
  email: z.string(),
  name: z.string(),
  role: z.lazy(() => UserRoleSchema).optional(),
  createdAt: z.coerce.date().optional(),
  updatedAt: z.coerce.date().optional(),
  company: z.lazy(() => CompanyCreateNestedOneWithoutUsersInputSchema),
  signatures: z.lazy(() => SignatureCreateNestedManyWithoutUserInputSchema).optional(),
  apiKeys: z.lazy(() => ApiKeyCreateNestedManyWithoutUserInputSchema).optional()
}).strict();

export const UserUncheckedCreateWithoutDocumentsInputSchema: z.ZodType<Prisma.UserUncheckedCreateWithoutDocumentsInput> = z.object({
  id: z.string().uuid().optional(),
  email: z.string(),
  name: z.string(),
  companyId: z.number().int(),
  role: z.lazy(() => UserRoleSchema).optional(),
  createdAt: z.coerce.date().optional(),
  updatedAt: z.coerce.date().optional(),
  signatures: z.lazy(() => SignatureUncheckedCreateNestedManyWithoutUserInputSchema).optional(),
  apiKeys: z.lazy(() => ApiKeyUncheckedCreateNestedManyWithoutUserInputSchema).optional()
}).strict();

export const UserCreateOrConnectWithoutDocumentsInputSchema: z.ZodType<Prisma.UserCreateOrConnectWithoutDocumentsInput> = z.object({
  where: z.lazy(() => UserWhereUniqueInputSchema),
  create: z.union([ z.lazy(() => UserCreateWithoutDocumentsInputSchema),z.lazy(() => UserUncheckedCreateWithoutDocumentsInputSchema) ]),
}).strict();

export const CompanyCreateWithoutDocumentsInputSchema: z.ZodType<Prisma.CompanyCreateWithoutDocumentsInput> = z.object({
  id: z.number().int(),
  name: z.string(),
  adminEmail: z.string(),
  country: z.string(),
  rootCertificate: z.string().optional().nullable(),
  subscriptionId: z.string().optional().nullable(),
  createdAt: z.coerce.date().optional(),
  updatedAt: z.coerce.date().optional(),
  users: z.lazy(() => UserCreateNestedManyWithoutCompanyInputSchema).optional(),
  certificates: z.lazy(() => CertificateCreateNestedManyWithoutCompanyInputSchema).optional(),
  blockchainWallet: z.lazy(() => BlockchainWalletCreateNestedOneWithoutCompanyInputSchema).optional(),
  SigningTemplate: z.lazy(() => SigningTemplateCreateNestedManyWithoutCompanyInputSchema).optional(),
  ApiKey: z.lazy(() => ApiKeyCreateNestedManyWithoutCompanyInputSchema).optional()
}).strict();

export const CompanyUncheckedCreateWithoutDocumentsInputSchema: z.ZodType<Prisma.CompanyUncheckedCreateWithoutDocumentsInput> = z.object({
  id: z.number().int(),
  name: z.string(),
  adminEmail: z.string(),
  country: z.string(),
  rootCertificate: z.string().optional().nullable(),
  subscriptionId: z.string().optional().nullable(),
  createdAt: z.coerce.date().optional(),
  updatedAt: z.coerce.date().optional(),
  users: z.lazy(() => UserUncheckedCreateNestedManyWithoutCompanyInputSchema).optional(),
  certificates: z.lazy(() => CertificateUncheckedCreateNestedManyWithoutCompanyInputSchema).optional(),
  blockchainWallet: z.lazy(() => BlockchainWalletUncheckedCreateNestedOneWithoutCompanyInputSchema).optional(),
  SigningTemplate: z.lazy(() => SigningTemplateUncheckedCreateNestedManyWithoutCompanyInputSchema).optional(),
  ApiKey: z.lazy(() => ApiKeyUncheckedCreateNestedManyWithoutCompanyInputSchema).optional()
}).strict();

export const CompanyCreateOrConnectWithoutDocumentsInputSchema: z.ZodType<Prisma.CompanyCreateOrConnectWithoutDocumentsInput> = z.object({
  where: z.lazy(() => CompanyWhereUniqueInputSchema),
  create: z.union([ z.lazy(() => CompanyCreateWithoutDocumentsInputSchema),z.lazy(() => CompanyUncheckedCreateWithoutDocumentsInputSchema) ]),
}).strict();

export const SigningTemplateCreateWithoutDocumentsInputSchema: z.ZodType<Prisma.SigningTemplateCreateWithoutDocumentsInput> = z.object({
  id: z.string().uuid().optional(),
  name: z.string(),
  fields: z.union([ z.lazy(() => JsonNullValueInputSchema),InputJsonValueSchema ]),
  createdAt: z.coerce.date().optional(),
  updatedAt: z.coerce.date().optional(),
  company: z.lazy(() => CompanyCreateNestedOneWithoutSigningTemplateInputSchema)
}).strict();

export const SigningTemplateUncheckedCreateWithoutDocumentsInputSchema: z.ZodType<Prisma.SigningTemplateUncheckedCreateWithoutDocumentsInput> = z.object({
  id: z.string().uuid().optional(),
  name: z.string(),
  companyId: z.number().int(),
  fields: z.union([ z.lazy(() => JsonNullValueInputSchema),InputJsonValueSchema ]),
  createdAt: z.coerce.date().optional(),
  updatedAt: z.coerce.date().optional()
}).strict();

export const SigningTemplateCreateOrConnectWithoutDocumentsInputSchema: z.ZodType<Prisma.SigningTemplateCreateOrConnectWithoutDocumentsInput> = z.object({
  where: z.lazy(() => SigningTemplateWhereUniqueInputSchema),
  create: z.union([ z.lazy(() => SigningTemplateCreateWithoutDocumentsInputSchema),z.lazy(() => SigningTemplateUncheckedCreateWithoutDocumentsInputSchema) ]),
}).strict();

export const DocumentSignerCreateWithoutDocumentInputSchema: z.ZodType<Prisma.DocumentSignerCreateWithoutDocumentInput> = z.object({
  id: z.string().uuid().optional(),
  email: z.string(),
  name: z.string().optional().nullable(),
  order: z.number().int(),
  status: z.lazy(() => SignerStatusSchema).optional(),
  expiresAt: z.coerce.date().optional().nullable(),
  notifiedAt: z.coerce.date().optional().nullable(),
  createdAt: z.coerce.date().optional(),
  updatedAt: z.coerce.date().optional(),
  signatureFields: z.lazy(() => SignatureFieldCreateNestedManyWithoutSignerInputSchema).optional(),
  signature: z.lazy(() => SignatureCreateNestedOneWithoutDocumentSignerInputSchema).optional()
}).strict();

export const DocumentSignerUncheckedCreateWithoutDocumentInputSchema: z.ZodType<Prisma.DocumentSignerUncheckedCreateWithoutDocumentInput> = z.object({
  id: z.string().uuid().optional(),
  email: z.string(),
  name: z.string().optional().nullable(),
  order: z.number().int(),
  status: z.lazy(() => SignerStatusSchema).optional(),
  expiresAt: z.coerce.date().optional().nullable(),
  notifiedAt: z.coerce.date().optional().nullable(),
  createdAt: z.coerce.date().optional(),
  updatedAt: z.coerce.date().optional(),
  signatureId: z.string().optional().nullable(),
  signatureFields: z.lazy(() => SignatureFieldUncheckedCreateNestedManyWithoutSignerInputSchema).optional()
}).strict();

export const DocumentSignerCreateOrConnectWithoutDocumentInputSchema: z.ZodType<Prisma.DocumentSignerCreateOrConnectWithoutDocumentInput> = z.object({
  where: z.lazy(() => DocumentSignerWhereUniqueInputSchema),
  create: z.union([ z.lazy(() => DocumentSignerCreateWithoutDocumentInputSchema),z.lazy(() => DocumentSignerUncheckedCreateWithoutDocumentInputSchema) ]),
}).strict();

export const DocumentSignerCreateManyDocumentInputEnvelopeSchema: z.ZodType<Prisma.DocumentSignerCreateManyDocumentInputEnvelope> = z.object({
  data: z.union([ z.lazy(() => DocumentSignerCreateManyDocumentInputSchema),z.lazy(() => DocumentSignerCreateManyDocumentInputSchema).array() ]),
  skipDuplicates: z.boolean().optional()
}).strict();

export const SignatureCreateWithoutDocumentInputSchema: z.ZodType<Prisma.SignatureCreateWithoutDocumentInput> = z.object({
  id: z.string().uuid().optional(),
  signatureData: z.string(),
  visualSignature: z.string().optional().nullable(),
  blockchainTx: z.string().optional().nullable(),
  coordinates: z.union([ z.lazy(() => NullableJsonNullValueInputSchema),InputJsonValueSchema ]).optional(),
  metadata: z.union([ z.lazy(() => NullableJsonNullValueInputSchema),InputJsonValueSchema ]).optional(),
  createdAt: z.coerce.date().optional(),
  updatedAt: z.coerce.date().optional(),
  user: z.lazy(() => UserCreateNestedOneWithoutSignaturesInputSchema),
  certificate: z.lazy(() => CertificateCreateNestedOneWithoutSignaturesInputSchema),
  DocumentSigner: z.lazy(() => DocumentSignerCreateNestedManyWithoutSignatureInputSchema).optional()
}).strict();

export const SignatureUncheckedCreateWithoutDocumentInputSchema: z.ZodType<Prisma.SignatureUncheckedCreateWithoutDocumentInput> = z.object({
  id: z.string().uuid().optional(),
  userId: z.string(),
  certificateId: z.string(),
  signatureData: z.string(),
  visualSignature: z.string().optional().nullable(),
  blockchainTx: z.string().optional().nullable(),
  coordinates: z.union([ z.lazy(() => NullableJsonNullValueInputSchema),InputJsonValueSchema ]).optional(),
  metadata: z.union([ z.lazy(() => NullableJsonNullValueInputSchema),InputJsonValueSchema ]).optional(),
  createdAt: z.coerce.date().optional(),
  updatedAt: z.coerce.date().optional(),
  DocumentSigner: z.lazy(() => DocumentSignerUncheckedCreateNestedManyWithoutSignatureInputSchema).optional()
}).strict();

export const SignatureCreateOrConnectWithoutDocumentInputSchema: z.ZodType<Prisma.SignatureCreateOrConnectWithoutDocumentInput> = z.object({
  where: z.lazy(() => SignatureWhereUniqueInputSchema),
  create: z.union([ z.lazy(() => SignatureCreateWithoutDocumentInputSchema),z.lazy(() => SignatureUncheckedCreateWithoutDocumentInputSchema) ]),
}).strict();

export const SignatureCreateManyDocumentInputEnvelopeSchema: z.ZodType<Prisma.SignatureCreateManyDocumentInputEnvelope> = z.object({
  data: z.union([ z.lazy(() => SignatureCreateManyDocumentInputSchema),z.lazy(() => SignatureCreateManyDocumentInputSchema).array() ]),
  skipDuplicates: z.boolean().optional()
}).strict();

export const AuditLogCreateWithoutDocumentInputSchema: z.ZodType<Prisma.AuditLogCreateWithoutDocumentInput> = z.object({
  id: z.string().uuid().optional(),
  action: z.string(),
  userId: z.string().optional().nullable(),
  metadata: z.union([ z.lazy(() => NullableJsonNullValueInputSchema),InputJsonValueSchema ]).optional(),
  createdAt: z.coerce.date().optional()
}).strict();

export const AuditLogUncheckedCreateWithoutDocumentInputSchema: z.ZodType<Prisma.AuditLogUncheckedCreateWithoutDocumentInput> = z.object({
  id: z.string().uuid().optional(),
  action: z.string(),
  userId: z.string().optional().nullable(),
  metadata: z.union([ z.lazy(() => NullableJsonNullValueInputSchema),InputJsonValueSchema ]).optional(),
  createdAt: z.coerce.date().optional()
}).strict();

export const AuditLogCreateOrConnectWithoutDocumentInputSchema: z.ZodType<Prisma.AuditLogCreateOrConnectWithoutDocumentInput> = z.object({
  where: z.lazy(() => AuditLogWhereUniqueInputSchema),
  create: z.union([ z.lazy(() => AuditLogCreateWithoutDocumentInputSchema),z.lazy(() => AuditLogUncheckedCreateWithoutDocumentInputSchema) ]),
}).strict();

export const AuditLogCreateManyDocumentInputEnvelopeSchema: z.ZodType<Prisma.AuditLogCreateManyDocumentInputEnvelope> = z.object({
  data: z.union([ z.lazy(() => AuditLogCreateManyDocumentInputSchema),z.lazy(() => AuditLogCreateManyDocumentInputSchema).array() ]),
  skipDuplicates: z.boolean().optional()
}).strict();

export const SignatureFieldCreateWithoutDocumentInputSchema: z.ZodType<Prisma.SignatureFieldCreateWithoutDocumentInput> = z.object({
  id: z.string().uuid().optional(),
  type: z.lazy(() => FieldTypeSchema).optional(),
  required: z.boolean().optional(),
  page: z.number().int(),
  x: z.number(),
  y: z.number(),
  width: z.number(),
  height: z.number(),
  signedAt: z.coerce.date().optional().nullable(),
  createdAt: z.coerce.date().optional(),
  updatedAt: z.coerce.date().optional(),
  signer: z.lazy(() => DocumentSignerCreateNestedOneWithoutSignatureFieldsInputSchema)
}).strict();

export const SignatureFieldUncheckedCreateWithoutDocumentInputSchema: z.ZodType<Prisma.SignatureFieldUncheckedCreateWithoutDocumentInput> = z.object({
  id: z.string().uuid().optional(),
  signerId: z.string(),
  type: z.lazy(() => FieldTypeSchema).optional(),
  required: z.boolean().optional(),
  page: z.number().int(),
  x: z.number(),
  y: z.number(),
  width: z.number(),
  height: z.number(),
  signedAt: z.coerce.date().optional().nullable(),
  createdAt: z.coerce.date().optional(),
  updatedAt: z.coerce.date().optional()
}).strict();

export const SignatureFieldCreateOrConnectWithoutDocumentInputSchema: z.ZodType<Prisma.SignatureFieldCreateOrConnectWithoutDocumentInput> = z.object({
  where: z.lazy(() => SignatureFieldWhereUniqueInputSchema),
  create: z.union([ z.lazy(() => SignatureFieldCreateWithoutDocumentInputSchema),z.lazy(() => SignatureFieldUncheckedCreateWithoutDocumentInputSchema) ]),
}).strict();

export const SignatureFieldCreateManyDocumentInputEnvelopeSchema: z.ZodType<Prisma.SignatureFieldCreateManyDocumentInputEnvelope> = z.object({
  data: z.union([ z.lazy(() => SignatureFieldCreateManyDocumentInputSchema),z.lazy(() => SignatureFieldCreateManyDocumentInputSchema).array() ]),
  skipDuplicates: z.boolean().optional()
}).strict();

export const UserUpsertWithoutDocumentsInputSchema: z.ZodType<Prisma.UserUpsertWithoutDocumentsInput> = z.object({
  update: z.union([ z.lazy(() => UserUpdateWithoutDocumentsInputSchema),z.lazy(() => UserUncheckedUpdateWithoutDocumentsInputSchema) ]),
  create: z.union([ z.lazy(() => UserCreateWithoutDocumentsInputSchema),z.lazy(() => UserUncheckedCreateWithoutDocumentsInputSchema) ]),
  where: z.lazy(() => UserWhereInputSchema).optional()
}).strict();

export const UserUpdateToOneWithWhereWithoutDocumentsInputSchema: z.ZodType<Prisma.UserUpdateToOneWithWhereWithoutDocumentsInput> = z.object({
  where: z.lazy(() => UserWhereInputSchema).optional(),
  data: z.union([ z.lazy(() => UserUpdateWithoutDocumentsInputSchema),z.lazy(() => UserUncheckedUpdateWithoutDocumentsInputSchema) ]),
}).strict();

export const UserUpdateWithoutDocumentsInputSchema: z.ZodType<Prisma.UserUpdateWithoutDocumentsInput> = z.object({
  id: z.union([ z.string().uuid(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  email: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  name: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  role: z.union([ z.lazy(() => UserRoleSchema),z.lazy(() => EnumUserRoleFieldUpdateOperationsInputSchema) ]).optional(),
  createdAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  updatedAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  company: z.lazy(() => CompanyUpdateOneRequiredWithoutUsersNestedInputSchema).optional(),
  signatures: z.lazy(() => SignatureUpdateManyWithoutUserNestedInputSchema).optional(),
  apiKeys: z.lazy(() => ApiKeyUpdateManyWithoutUserNestedInputSchema).optional()
}).strict();

export const UserUncheckedUpdateWithoutDocumentsInputSchema: z.ZodType<Prisma.UserUncheckedUpdateWithoutDocumentsInput> = z.object({
  id: z.union([ z.string().uuid(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  email: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  name: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  companyId: z.union([ z.number().int(),z.lazy(() => IntFieldUpdateOperationsInputSchema) ]).optional(),
  role: z.union([ z.lazy(() => UserRoleSchema),z.lazy(() => EnumUserRoleFieldUpdateOperationsInputSchema) ]).optional(),
  createdAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  updatedAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  signatures: z.lazy(() => SignatureUncheckedUpdateManyWithoutUserNestedInputSchema).optional(),
  apiKeys: z.lazy(() => ApiKeyUncheckedUpdateManyWithoutUserNestedInputSchema).optional()
}).strict();

export const CompanyUpsertWithoutDocumentsInputSchema: z.ZodType<Prisma.CompanyUpsertWithoutDocumentsInput> = z.object({
  update: z.union([ z.lazy(() => CompanyUpdateWithoutDocumentsInputSchema),z.lazy(() => CompanyUncheckedUpdateWithoutDocumentsInputSchema) ]),
  create: z.union([ z.lazy(() => CompanyCreateWithoutDocumentsInputSchema),z.lazy(() => CompanyUncheckedCreateWithoutDocumentsInputSchema) ]),
  where: z.lazy(() => CompanyWhereInputSchema).optional()
}).strict();

export const CompanyUpdateToOneWithWhereWithoutDocumentsInputSchema: z.ZodType<Prisma.CompanyUpdateToOneWithWhereWithoutDocumentsInput> = z.object({
  where: z.lazy(() => CompanyWhereInputSchema).optional(),
  data: z.union([ z.lazy(() => CompanyUpdateWithoutDocumentsInputSchema),z.lazy(() => CompanyUncheckedUpdateWithoutDocumentsInputSchema) ]),
}).strict();

export const CompanyUpdateWithoutDocumentsInputSchema: z.ZodType<Prisma.CompanyUpdateWithoutDocumentsInput> = z.object({
  id: z.union([ z.number().int(),z.lazy(() => IntFieldUpdateOperationsInputSchema) ]).optional(),
  name: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  adminEmail: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  country: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  rootCertificate: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  subscriptionId: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  createdAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  updatedAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  users: z.lazy(() => UserUpdateManyWithoutCompanyNestedInputSchema).optional(),
  certificates: z.lazy(() => CertificateUpdateManyWithoutCompanyNestedInputSchema).optional(),
  blockchainWallet: z.lazy(() => BlockchainWalletUpdateOneWithoutCompanyNestedInputSchema).optional(),
  SigningTemplate: z.lazy(() => SigningTemplateUpdateManyWithoutCompanyNestedInputSchema).optional(),
  ApiKey: z.lazy(() => ApiKeyUpdateManyWithoutCompanyNestedInputSchema).optional()
}).strict();

export const CompanyUncheckedUpdateWithoutDocumentsInputSchema: z.ZodType<Prisma.CompanyUncheckedUpdateWithoutDocumentsInput> = z.object({
  id: z.union([ z.number().int(),z.lazy(() => IntFieldUpdateOperationsInputSchema) ]).optional(),
  name: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  adminEmail: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  country: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  rootCertificate: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  subscriptionId: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  createdAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  updatedAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  users: z.lazy(() => UserUncheckedUpdateManyWithoutCompanyNestedInputSchema).optional(),
  certificates: z.lazy(() => CertificateUncheckedUpdateManyWithoutCompanyNestedInputSchema).optional(),
  blockchainWallet: z.lazy(() => BlockchainWalletUncheckedUpdateOneWithoutCompanyNestedInputSchema).optional(),
  SigningTemplate: z.lazy(() => SigningTemplateUncheckedUpdateManyWithoutCompanyNestedInputSchema).optional(),
  ApiKey: z.lazy(() => ApiKeyUncheckedUpdateManyWithoutCompanyNestedInputSchema).optional()
}).strict();

export const SigningTemplateUpsertWithoutDocumentsInputSchema: z.ZodType<Prisma.SigningTemplateUpsertWithoutDocumentsInput> = z.object({
  update: z.union([ z.lazy(() => SigningTemplateUpdateWithoutDocumentsInputSchema),z.lazy(() => SigningTemplateUncheckedUpdateWithoutDocumentsInputSchema) ]),
  create: z.union([ z.lazy(() => SigningTemplateCreateWithoutDocumentsInputSchema),z.lazy(() => SigningTemplateUncheckedCreateWithoutDocumentsInputSchema) ]),
  where: z.lazy(() => SigningTemplateWhereInputSchema).optional()
}).strict();

export const SigningTemplateUpdateToOneWithWhereWithoutDocumentsInputSchema: z.ZodType<Prisma.SigningTemplateUpdateToOneWithWhereWithoutDocumentsInput> = z.object({
  where: z.lazy(() => SigningTemplateWhereInputSchema).optional(),
  data: z.union([ z.lazy(() => SigningTemplateUpdateWithoutDocumentsInputSchema),z.lazy(() => SigningTemplateUncheckedUpdateWithoutDocumentsInputSchema) ]),
}).strict();

export const SigningTemplateUpdateWithoutDocumentsInputSchema: z.ZodType<Prisma.SigningTemplateUpdateWithoutDocumentsInput> = z.object({
  id: z.union([ z.string().uuid(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  name: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  fields: z.union([ z.lazy(() => JsonNullValueInputSchema),InputJsonValueSchema ]).optional(),
  createdAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  updatedAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  company: z.lazy(() => CompanyUpdateOneRequiredWithoutSigningTemplateNestedInputSchema).optional()
}).strict();

export const SigningTemplateUncheckedUpdateWithoutDocumentsInputSchema: z.ZodType<Prisma.SigningTemplateUncheckedUpdateWithoutDocumentsInput> = z.object({
  id: z.union([ z.string().uuid(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  name: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  companyId: z.union([ z.number().int(),z.lazy(() => IntFieldUpdateOperationsInputSchema) ]).optional(),
  fields: z.union([ z.lazy(() => JsonNullValueInputSchema),InputJsonValueSchema ]).optional(),
  createdAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  updatedAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
}).strict();

export const DocumentSignerUpsertWithWhereUniqueWithoutDocumentInputSchema: z.ZodType<Prisma.DocumentSignerUpsertWithWhereUniqueWithoutDocumentInput> = z.object({
  where: z.lazy(() => DocumentSignerWhereUniqueInputSchema),
  update: z.union([ z.lazy(() => DocumentSignerUpdateWithoutDocumentInputSchema),z.lazy(() => DocumentSignerUncheckedUpdateWithoutDocumentInputSchema) ]),
  create: z.union([ z.lazy(() => DocumentSignerCreateWithoutDocumentInputSchema),z.lazy(() => DocumentSignerUncheckedCreateWithoutDocumentInputSchema) ]),
}).strict();

export const DocumentSignerUpdateWithWhereUniqueWithoutDocumentInputSchema: z.ZodType<Prisma.DocumentSignerUpdateWithWhereUniqueWithoutDocumentInput> = z.object({
  where: z.lazy(() => DocumentSignerWhereUniqueInputSchema),
  data: z.union([ z.lazy(() => DocumentSignerUpdateWithoutDocumentInputSchema),z.lazy(() => DocumentSignerUncheckedUpdateWithoutDocumentInputSchema) ]),
}).strict();

export const DocumentSignerUpdateManyWithWhereWithoutDocumentInputSchema: z.ZodType<Prisma.DocumentSignerUpdateManyWithWhereWithoutDocumentInput> = z.object({
  where: z.lazy(() => DocumentSignerScalarWhereInputSchema),
  data: z.union([ z.lazy(() => DocumentSignerUpdateManyMutationInputSchema),z.lazy(() => DocumentSignerUncheckedUpdateManyWithoutDocumentInputSchema) ]),
}).strict();

export const DocumentSignerScalarWhereInputSchema: z.ZodType<Prisma.DocumentSignerScalarWhereInput> = z.object({
  AND: z.union([ z.lazy(() => DocumentSignerScalarWhereInputSchema),z.lazy(() => DocumentSignerScalarWhereInputSchema).array() ]).optional(),
  OR: z.lazy(() => DocumentSignerScalarWhereInputSchema).array().optional(),
  NOT: z.union([ z.lazy(() => DocumentSignerScalarWhereInputSchema),z.lazy(() => DocumentSignerScalarWhereInputSchema).array() ]).optional(),
  id: z.union([ z.lazy(() => StringFilterSchema),z.string() ]).optional(),
  documentId: z.union([ z.lazy(() => StringFilterSchema),z.string() ]).optional(),
  email: z.union([ z.lazy(() => StringFilterSchema),z.string() ]).optional(),
  name: z.union([ z.lazy(() => StringNullableFilterSchema),z.string() ]).optional().nullable(),
  order: z.union([ z.lazy(() => IntFilterSchema),z.number() ]).optional(),
  status: z.union([ z.lazy(() => EnumSignerStatusFilterSchema),z.lazy(() => SignerStatusSchema) ]).optional(),
  expiresAt: z.union([ z.lazy(() => DateTimeNullableFilterSchema),z.coerce.date() ]).optional().nullable(),
  notifiedAt: z.union([ z.lazy(() => DateTimeNullableFilterSchema),z.coerce.date() ]).optional().nullable(),
  createdAt: z.union([ z.lazy(() => DateTimeFilterSchema),z.coerce.date() ]).optional(),
  updatedAt: z.union([ z.lazy(() => DateTimeFilterSchema),z.coerce.date() ]).optional(),
  signatureId: z.union([ z.lazy(() => StringNullableFilterSchema),z.string() ]).optional().nullable(),
}).strict();

export const SignatureUpsertWithWhereUniqueWithoutDocumentInputSchema: z.ZodType<Prisma.SignatureUpsertWithWhereUniqueWithoutDocumentInput> = z.object({
  where: z.lazy(() => SignatureWhereUniqueInputSchema),
  update: z.union([ z.lazy(() => SignatureUpdateWithoutDocumentInputSchema),z.lazy(() => SignatureUncheckedUpdateWithoutDocumentInputSchema) ]),
  create: z.union([ z.lazy(() => SignatureCreateWithoutDocumentInputSchema),z.lazy(() => SignatureUncheckedCreateWithoutDocumentInputSchema) ]),
}).strict();

export const SignatureUpdateWithWhereUniqueWithoutDocumentInputSchema: z.ZodType<Prisma.SignatureUpdateWithWhereUniqueWithoutDocumentInput> = z.object({
  where: z.lazy(() => SignatureWhereUniqueInputSchema),
  data: z.union([ z.lazy(() => SignatureUpdateWithoutDocumentInputSchema),z.lazy(() => SignatureUncheckedUpdateWithoutDocumentInputSchema) ]),
}).strict();

export const SignatureUpdateManyWithWhereWithoutDocumentInputSchema: z.ZodType<Prisma.SignatureUpdateManyWithWhereWithoutDocumentInput> = z.object({
  where: z.lazy(() => SignatureScalarWhereInputSchema),
  data: z.union([ z.lazy(() => SignatureUpdateManyMutationInputSchema),z.lazy(() => SignatureUncheckedUpdateManyWithoutDocumentInputSchema) ]),
}).strict();

export const AuditLogUpsertWithWhereUniqueWithoutDocumentInputSchema: z.ZodType<Prisma.AuditLogUpsertWithWhereUniqueWithoutDocumentInput> = z.object({
  where: z.lazy(() => AuditLogWhereUniqueInputSchema),
  update: z.union([ z.lazy(() => AuditLogUpdateWithoutDocumentInputSchema),z.lazy(() => AuditLogUncheckedUpdateWithoutDocumentInputSchema) ]),
  create: z.union([ z.lazy(() => AuditLogCreateWithoutDocumentInputSchema),z.lazy(() => AuditLogUncheckedCreateWithoutDocumentInputSchema) ]),
}).strict();

export const AuditLogUpdateWithWhereUniqueWithoutDocumentInputSchema: z.ZodType<Prisma.AuditLogUpdateWithWhereUniqueWithoutDocumentInput> = z.object({
  where: z.lazy(() => AuditLogWhereUniqueInputSchema),
  data: z.union([ z.lazy(() => AuditLogUpdateWithoutDocumentInputSchema),z.lazy(() => AuditLogUncheckedUpdateWithoutDocumentInputSchema) ]),
}).strict();

export const AuditLogUpdateManyWithWhereWithoutDocumentInputSchema: z.ZodType<Prisma.AuditLogUpdateManyWithWhereWithoutDocumentInput> = z.object({
  where: z.lazy(() => AuditLogScalarWhereInputSchema),
  data: z.union([ z.lazy(() => AuditLogUpdateManyMutationInputSchema),z.lazy(() => AuditLogUncheckedUpdateManyWithoutDocumentInputSchema) ]),
}).strict();

export const AuditLogScalarWhereInputSchema: z.ZodType<Prisma.AuditLogScalarWhereInput> = z.object({
  AND: z.union([ z.lazy(() => AuditLogScalarWhereInputSchema),z.lazy(() => AuditLogScalarWhereInputSchema).array() ]).optional(),
  OR: z.lazy(() => AuditLogScalarWhereInputSchema).array().optional(),
  NOT: z.union([ z.lazy(() => AuditLogScalarWhereInputSchema),z.lazy(() => AuditLogScalarWhereInputSchema).array() ]).optional(),
  id: z.union([ z.lazy(() => StringFilterSchema),z.string() ]).optional(),
  documentId: z.union([ z.lazy(() => StringFilterSchema),z.string() ]).optional(),
  action: z.union([ z.lazy(() => StringFilterSchema),z.string() ]).optional(),
  userId: z.union([ z.lazy(() => StringNullableFilterSchema),z.string() ]).optional().nullable(),
  metadata: z.lazy(() => JsonNullableFilterSchema).optional(),
  createdAt: z.union([ z.lazy(() => DateTimeFilterSchema),z.coerce.date() ]).optional(),
}).strict();

export const SignatureFieldUpsertWithWhereUniqueWithoutDocumentInputSchema: z.ZodType<Prisma.SignatureFieldUpsertWithWhereUniqueWithoutDocumentInput> = z.object({
  where: z.lazy(() => SignatureFieldWhereUniqueInputSchema),
  update: z.union([ z.lazy(() => SignatureFieldUpdateWithoutDocumentInputSchema),z.lazy(() => SignatureFieldUncheckedUpdateWithoutDocumentInputSchema) ]),
  create: z.union([ z.lazy(() => SignatureFieldCreateWithoutDocumentInputSchema),z.lazy(() => SignatureFieldUncheckedCreateWithoutDocumentInputSchema) ]),
}).strict();

export const SignatureFieldUpdateWithWhereUniqueWithoutDocumentInputSchema: z.ZodType<Prisma.SignatureFieldUpdateWithWhereUniqueWithoutDocumentInput> = z.object({
  where: z.lazy(() => SignatureFieldWhereUniqueInputSchema),
  data: z.union([ z.lazy(() => SignatureFieldUpdateWithoutDocumentInputSchema),z.lazy(() => SignatureFieldUncheckedUpdateWithoutDocumentInputSchema) ]),
}).strict();

export const SignatureFieldUpdateManyWithWhereWithoutDocumentInputSchema: z.ZodType<Prisma.SignatureFieldUpdateManyWithWhereWithoutDocumentInput> = z.object({
  where: z.lazy(() => SignatureFieldScalarWhereInputSchema),
  data: z.union([ z.lazy(() => SignatureFieldUpdateManyMutationInputSchema),z.lazy(() => SignatureFieldUncheckedUpdateManyWithoutDocumentInputSchema) ]),
}).strict();

export const SignatureFieldScalarWhereInputSchema: z.ZodType<Prisma.SignatureFieldScalarWhereInput> = z.object({
  AND: z.union([ z.lazy(() => SignatureFieldScalarWhereInputSchema),z.lazy(() => SignatureFieldScalarWhereInputSchema).array() ]).optional(),
  OR: z.lazy(() => SignatureFieldScalarWhereInputSchema).array().optional(),
  NOT: z.union([ z.lazy(() => SignatureFieldScalarWhereInputSchema),z.lazy(() => SignatureFieldScalarWhereInputSchema).array() ]).optional(),
  id: z.union([ z.lazy(() => StringFilterSchema),z.string() ]).optional(),
  documentId: z.union([ z.lazy(() => StringFilterSchema),z.string() ]).optional(),
  signerId: z.union([ z.lazy(() => StringFilterSchema),z.string() ]).optional(),
  type: z.union([ z.lazy(() => EnumFieldTypeFilterSchema),z.lazy(() => FieldTypeSchema) ]).optional(),
  required: z.union([ z.lazy(() => BoolFilterSchema),z.boolean() ]).optional(),
  page: z.union([ z.lazy(() => IntFilterSchema),z.number() ]).optional(),
  x: z.union([ z.lazy(() => FloatFilterSchema),z.number() ]).optional(),
  y: z.union([ z.lazy(() => FloatFilterSchema),z.number() ]).optional(),
  width: z.union([ z.lazy(() => FloatFilterSchema),z.number() ]).optional(),
  height: z.union([ z.lazy(() => FloatFilterSchema),z.number() ]).optional(),
  signedAt: z.union([ z.lazy(() => DateTimeNullableFilterSchema),z.coerce.date() ]).optional().nullable(),
  createdAt: z.union([ z.lazy(() => DateTimeFilterSchema),z.coerce.date() ]).optional(),
  updatedAt: z.union([ z.lazy(() => DateTimeFilterSchema),z.coerce.date() ]).optional(),
}).strict();

export const DocumentCreateWithoutSignersInputSchema: z.ZodType<Prisma.DocumentCreateWithoutSignersInput> = z.object({
  id: z.string().uuid().optional(),
  title: z.string().optional().nullable(),
  description: z.string().optional().nullable(),
  status: z.lazy(() => DocumentStatusSchema).optional(),
  fileUrl: z.string(),
  fileHash: z.string().optional().nullable(),
  blockchainDocId: z.string().optional().nullable(),
  metadata: z.union([ z.lazy(() => NullableJsonNullValueInputSchema),InputJsonValueSchema ]).optional(),
  expiresAt: z.coerce.date().optional().nullable(),
  createdAt: z.coerce.date().optional(),
  updatedAt: z.coerce.date().optional(),
  user: z.lazy(() => UserCreateNestedOneWithoutDocumentsInputSchema),
  company: z.lazy(() => CompanyCreateNestedOneWithoutDocumentsInputSchema),
  signingTemplate: z.lazy(() => SigningTemplateCreateNestedOneWithoutDocumentsInputSchema).optional(),
  signatures: z.lazy(() => SignatureCreateNestedManyWithoutDocumentInputSchema).optional(),
  auditLogs: z.lazy(() => AuditLogCreateNestedManyWithoutDocumentInputSchema).optional(),
  SignatureField: z.lazy(() => SignatureFieldCreateNestedManyWithoutDocumentInputSchema).optional()
}).strict();

export const DocumentUncheckedCreateWithoutSignersInputSchema: z.ZodType<Prisma.DocumentUncheckedCreateWithoutSignersInput> = z.object({
  id: z.string().uuid().optional(),
  title: z.string().optional().nullable(),
  description: z.string().optional().nullable(),
  userId: z.string(),
  companyId: z.number().int(),
  status: z.lazy(() => DocumentStatusSchema).optional(),
  fileUrl: z.string(),
  fileHash: z.string().optional().nullable(),
  blockchainDocId: z.string().optional().nullable(),
  templateId: z.string().optional().nullable(),
  metadata: z.union([ z.lazy(() => NullableJsonNullValueInputSchema),InputJsonValueSchema ]).optional(),
  expiresAt: z.coerce.date().optional().nullable(),
  createdAt: z.coerce.date().optional(),
  updatedAt: z.coerce.date().optional(),
  signatures: z.lazy(() => SignatureUncheckedCreateNestedManyWithoutDocumentInputSchema).optional(),
  auditLogs: z.lazy(() => AuditLogUncheckedCreateNestedManyWithoutDocumentInputSchema).optional(),
  SignatureField: z.lazy(() => SignatureFieldUncheckedCreateNestedManyWithoutDocumentInputSchema).optional()
}).strict();

export const DocumentCreateOrConnectWithoutSignersInputSchema: z.ZodType<Prisma.DocumentCreateOrConnectWithoutSignersInput> = z.object({
  where: z.lazy(() => DocumentWhereUniqueInputSchema),
  create: z.union([ z.lazy(() => DocumentCreateWithoutSignersInputSchema),z.lazy(() => DocumentUncheckedCreateWithoutSignersInputSchema) ]),
}).strict();

export const SignatureFieldCreateWithoutSignerInputSchema: z.ZodType<Prisma.SignatureFieldCreateWithoutSignerInput> = z.object({
  id: z.string().uuid().optional(),
  type: z.lazy(() => FieldTypeSchema).optional(),
  required: z.boolean().optional(),
  page: z.number().int(),
  x: z.number(),
  y: z.number(),
  width: z.number(),
  height: z.number(),
  signedAt: z.coerce.date().optional().nullable(),
  createdAt: z.coerce.date().optional(),
  updatedAt: z.coerce.date().optional(),
  document: z.lazy(() => DocumentCreateNestedOneWithoutSignatureFieldInputSchema)
}).strict();

export const SignatureFieldUncheckedCreateWithoutSignerInputSchema: z.ZodType<Prisma.SignatureFieldUncheckedCreateWithoutSignerInput> = z.object({
  id: z.string().uuid().optional(),
  documentId: z.string(),
  type: z.lazy(() => FieldTypeSchema).optional(),
  required: z.boolean().optional(),
  page: z.number().int(),
  x: z.number(),
  y: z.number(),
  width: z.number(),
  height: z.number(),
  signedAt: z.coerce.date().optional().nullable(),
  createdAt: z.coerce.date().optional(),
  updatedAt: z.coerce.date().optional()
}).strict();

export const SignatureFieldCreateOrConnectWithoutSignerInputSchema: z.ZodType<Prisma.SignatureFieldCreateOrConnectWithoutSignerInput> = z.object({
  where: z.lazy(() => SignatureFieldWhereUniqueInputSchema),
  create: z.union([ z.lazy(() => SignatureFieldCreateWithoutSignerInputSchema),z.lazy(() => SignatureFieldUncheckedCreateWithoutSignerInputSchema) ]),
}).strict();

export const SignatureFieldCreateManySignerInputEnvelopeSchema: z.ZodType<Prisma.SignatureFieldCreateManySignerInputEnvelope> = z.object({
  data: z.union([ z.lazy(() => SignatureFieldCreateManySignerInputSchema),z.lazy(() => SignatureFieldCreateManySignerInputSchema).array() ]),
  skipDuplicates: z.boolean().optional()
}).strict();

export const SignatureCreateWithoutDocumentSignerInputSchema: z.ZodType<Prisma.SignatureCreateWithoutDocumentSignerInput> = z.object({
  id: z.string().uuid().optional(),
  signatureData: z.string(),
  visualSignature: z.string().optional().nullable(),
  blockchainTx: z.string().optional().nullable(),
  coordinates: z.union([ z.lazy(() => NullableJsonNullValueInputSchema),InputJsonValueSchema ]).optional(),
  metadata: z.union([ z.lazy(() => NullableJsonNullValueInputSchema),InputJsonValueSchema ]).optional(),
  createdAt: z.coerce.date().optional(),
  updatedAt: z.coerce.date().optional(),
  document: z.lazy(() => DocumentCreateNestedOneWithoutSignaturesInputSchema),
  user: z.lazy(() => UserCreateNestedOneWithoutSignaturesInputSchema),
  certificate: z.lazy(() => CertificateCreateNestedOneWithoutSignaturesInputSchema)
}).strict();

export const SignatureUncheckedCreateWithoutDocumentSignerInputSchema: z.ZodType<Prisma.SignatureUncheckedCreateWithoutDocumentSignerInput> = z.object({
  id: z.string().uuid().optional(),
  documentId: z.string(),
  userId: z.string(),
  certificateId: z.string(),
  signatureData: z.string(),
  visualSignature: z.string().optional().nullable(),
  blockchainTx: z.string().optional().nullable(),
  coordinates: z.union([ z.lazy(() => NullableJsonNullValueInputSchema),InputJsonValueSchema ]).optional(),
  metadata: z.union([ z.lazy(() => NullableJsonNullValueInputSchema),InputJsonValueSchema ]).optional(),
  createdAt: z.coerce.date().optional(),
  updatedAt: z.coerce.date().optional()
}).strict();

export const SignatureCreateOrConnectWithoutDocumentSignerInputSchema: z.ZodType<Prisma.SignatureCreateOrConnectWithoutDocumentSignerInput> = z.object({
  where: z.lazy(() => SignatureWhereUniqueInputSchema),
  create: z.union([ z.lazy(() => SignatureCreateWithoutDocumentSignerInputSchema),z.lazy(() => SignatureUncheckedCreateWithoutDocumentSignerInputSchema) ]),
}).strict();

export const DocumentUpsertWithoutSignersInputSchema: z.ZodType<Prisma.DocumentUpsertWithoutSignersInput> = z.object({
  update: z.union([ z.lazy(() => DocumentUpdateWithoutSignersInputSchema),z.lazy(() => DocumentUncheckedUpdateWithoutSignersInputSchema) ]),
  create: z.union([ z.lazy(() => DocumentCreateWithoutSignersInputSchema),z.lazy(() => DocumentUncheckedCreateWithoutSignersInputSchema) ]),
  where: z.lazy(() => DocumentWhereInputSchema).optional()
}).strict();

export const DocumentUpdateToOneWithWhereWithoutSignersInputSchema: z.ZodType<Prisma.DocumentUpdateToOneWithWhereWithoutSignersInput> = z.object({
  where: z.lazy(() => DocumentWhereInputSchema).optional(),
  data: z.union([ z.lazy(() => DocumentUpdateWithoutSignersInputSchema),z.lazy(() => DocumentUncheckedUpdateWithoutSignersInputSchema) ]),
}).strict();

export const DocumentUpdateWithoutSignersInputSchema: z.ZodType<Prisma.DocumentUpdateWithoutSignersInput> = z.object({
  id: z.union([ z.string().uuid(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  title: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  description: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  status: z.union([ z.lazy(() => DocumentStatusSchema),z.lazy(() => EnumDocumentStatusFieldUpdateOperationsInputSchema) ]).optional(),
  fileUrl: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  fileHash: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  blockchainDocId: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  metadata: z.union([ z.lazy(() => NullableJsonNullValueInputSchema),InputJsonValueSchema ]).optional(),
  expiresAt: z.union([ z.coerce.date(),z.lazy(() => NullableDateTimeFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  createdAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  updatedAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  user: z.lazy(() => UserUpdateOneRequiredWithoutDocumentsNestedInputSchema).optional(),
  company: z.lazy(() => CompanyUpdateOneRequiredWithoutDocumentsNestedInputSchema).optional(),
  signingTemplate: z.lazy(() => SigningTemplateUpdateOneWithoutDocumentsNestedInputSchema).optional(),
  signatures: z.lazy(() => SignatureUpdateManyWithoutDocumentNestedInputSchema).optional(),
  auditLogs: z.lazy(() => AuditLogUpdateManyWithoutDocumentNestedInputSchema).optional(),
  SignatureField: z.lazy(() => SignatureFieldUpdateManyWithoutDocumentNestedInputSchema).optional()
}).strict();

export const DocumentUncheckedUpdateWithoutSignersInputSchema: z.ZodType<Prisma.DocumentUncheckedUpdateWithoutSignersInput> = z.object({
  id: z.union([ z.string().uuid(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  title: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  description: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  userId: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  companyId: z.union([ z.number().int(),z.lazy(() => IntFieldUpdateOperationsInputSchema) ]).optional(),
  status: z.union([ z.lazy(() => DocumentStatusSchema),z.lazy(() => EnumDocumentStatusFieldUpdateOperationsInputSchema) ]).optional(),
  fileUrl: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  fileHash: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  blockchainDocId: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  templateId: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  metadata: z.union([ z.lazy(() => NullableJsonNullValueInputSchema),InputJsonValueSchema ]).optional(),
  expiresAt: z.union([ z.coerce.date(),z.lazy(() => NullableDateTimeFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  createdAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  updatedAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  signatures: z.lazy(() => SignatureUncheckedUpdateManyWithoutDocumentNestedInputSchema).optional(),
  auditLogs: z.lazy(() => AuditLogUncheckedUpdateManyWithoutDocumentNestedInputSchema).optional(),
  SignatureField: z.lazy(() => SignatureFieldUncheckedUpdateManyWithoutDocumentNestedInputSchema).optional()
}).strict();

export const SignatureFieldUpsertWithWhereUniqueWithoutSignerInputSchema: z.ZodType<Prisma.SignatureFieldUpsertWithWhereUniqueWithoutSignerInput> = z.object({
  where: z.lazy(() => SignatureFieldWhereUniqueInputSchema),
  update: z.union([ z.lazy(() => SignatureFieldUpdateWithoutSignerInputSchema),z.lazy(() => SignatureFieldUncheckedUpdateWithoutSignerInputSchema) ]),
  create: z.union([ z.lazy(() => SignatureFieldCreateWithoutSignerInputSchema),z.lazy(() => SignatureFieldUncheckedCreateWithoutSignerInputSchema) ]),
}).strict();

export const SignatureFieldUpdateWithWhereUniqueWithoutSignerInputSchema: z.ZodType<Prisma.SignatureFieldUpdateWithWhereUniqueWithoutSignerInput> = z.object({
  where: z.lazy(() => SignatureFieldWhereUniqueInputSchema),
  data: z.union([ z.lazy(() => SignatureFieldUpdateWithoutSignerInputSchema),z.lazy(() => SignatureFieldUncheckedUpdateWithoutSignerInputSchema) ]),
}).strict();

export const SignatureFieldUpdateManyWithWhereWithoutSignerInputSchema: z.ZodType<Prisma.SignatureFieldUpdateManyWithWhereWithoutSignerInput> = z.object({
  where: z.lazy(() => SignatureFieldScalarWhereInputSchema),
  data: z.union([ z.lazy(() => SignatureFieldUpdateManyMutationInputSchema),z.lazy(() => SignatureFieldUncheckedUpdateManyWithoutSignerInputSchema) ]),
}).strict();

export const SignatureUpsertWithoutDocumentSignerInputSchema: z.ZodType<Prisma.SignatureUpsertWithoutDocumentSignerInput> = z.object({
  update: z.union([ z.lazy(() => SignatureUpdateWithoutDocumentSignerInputSchema),z.lazy(() => SignatureUncheckedUpdateWithoutDocumentSignerInputSchema) ]),
  create: z.union([ z.lazy(() => SignatureCreateWithoutDocumentSignerInputSchema),z.lazy(() => SignatureUncheckedCreateWithoutDocumentSignerInputSchema) ]),
  where: z.lazy(() => SignatureWhereInputSchema).optional()
}).strict();

export const SignatureUpdateToOneWithWhereWithoutDocumentSignerInputSchema: z.ZodType<Prisma.SignatureUpdateToOneWithWhereWithoutDocumentSignerInput> = z.object({
  where: z.lazy(() => SignatureWhereInputSchema).optional(),
  data: z.union([ z.lazy(() => SignatureUpdateWithoutDocumentSignerInputSchema),z.lazy(() => SignatureUncheckedUpdateWithoutDocumentSignerInputSchema) ]),
}).strict();

export const SignatureUpdateWithoutDocumentSignerInputSchema: z.ZodType<Prisma.SignatureUpdateWithoutDocumentSignerInput> = z.object({
  id: z.union([ z.string().uuid(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  signatureData: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  visualSignature: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  blockchainTx: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  coordinates: z.union([ z.lazy(() => NullableJsonNullValueInputSchema),InputJsonValueSchema ]).optional(),
  metadata: z.union([ z.lazy(() => NullableJsonNullValueInputSchema),InputJsonValueSchema ]).optional(),
  createdAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  updatedAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  document: z.lazy(() => DocumentUpdateOneRequiredWithoutSignaturesNestedInputSchema).optional(),
  user: z.lazy(() => UserUpdateOneRequiredWithoutSignaturesNestedInputSchema).optional(),
  certificate: z.lazy(() => CertificateUpdateOneRequiredWithoutSignaturesNestedInputSchema).optional()
}).strict();

export const SignatureUncheckedUpdateWithoutDocumentSignerInputSchema: z.ZodType<Prisma.SignatureUncheckedUpdateWithoutDocumentSignerInput> = z.object({
  id: z.union([ z.string().uuid(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  documentId: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  userId: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  certificateId: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  signatureData: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  visualSignature: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  blockchainTx: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  coordinates: z.union([ z.lazy(() => NullableJsonNullValueInputSchema),InputJsonValueSchema ]).optional(),
  metadata: z.union([ z.lazy(() => NullableJsonNullValueInputSchema),InputJsonValueSchema ]).optional(),
  createdAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  updatedAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
}).strict();

export const DocumentCreateWithoutSignatureFieldInputSchema: z.ZodType<Prisma.DocumentCreateWithoutSignatureFieldInput> = z.object({
  id: z.string().uuid().optional(),
  title: z.string().optional().nullable(),
  description: z.string().optional().nullable(),
  status: z.lazy(() => DocumentStatusSchema).optional(),
  fileUrl: z.string(),
  fileHash: z.string().optional().nullable(),
  blockchainDocId: z.string().optional().nullable(),
  metadata: z.union([ z.lazy(() => NullableJsonNullValueInputSchema),InputJsonValueSchema ]).optional(),
  expiresAt: z.coerce.date().optional().nullable(),
  createdAt: z.coerce.date().optional(),
  updatedAt: z.coerce.date().optional(),
  user: z.lazy(() => UserCreateNestedOneWithoutDocumentsInputSchema),
  company: z.lazy(() => CompanyCreateNestedOneWithoutDocumentsInputSchema),
  signingTemplate: z.lazy(() => SigningTemplateCreateNestedOneWithoutDocumentsInputSchema).optional(),
  signers: z.lazy(() => DocumentSignerCreateNestedManyWithoutDocumentInputSchema).optional(),
  signatures: z.lazy(() => SignatureCreateNestedManyWithoutDocumentInputSchema).optional(),
  auditLogs: z.lazy(() => AuditLogCreateNestedManyWithoutDocumentInputSchema).optional()
}).strict();

export const DocumentUncheckedCreateWithoutSignatureFieldInputSchema: z.ZodType<Prisma.DocumentUncheckedCreateWithoutSignatureFieldInput> = z.object({
  id: z.string().uuid().optional(),
  title: z.string().optional().nullable(),
  description: z.string().optional().nullable(),
  userId: z.string(),
  companyId: z.number().int(),
  status: z.lazy(() => DocumentStatusSchema).optional(),
  fileUrl: z.string(),
  fileHash: z.string().optional().nullable(),
  blockchainDocId: z.string().optional().nullable(),
  templateId: z.string().optional().nullable(),
  metadata: z.union([ z.lazy(() => NullableJsonNullValueInputSchema),InputJsonValueSchema ]).optional(),
  expiresAt: z.coerce.date().optional().nullable(),
  createdAt: z.coerce.date().optional(),
  updatedAt: z.coerce.date().optional(),
  signers: z.lazy(() => DocumentSignerUncheckedCreateNestedManyWithoutDocumentInputSchema).optional(),
  signatures: z.lazy(() => SignatureUncheckedCreateNestedManyWithoutDocumentInputSchema).optional(),
  auditLogs: z.lazy(() => AuditLogUncheckedCreateNestedManyWithoutDocumentInputSchema).optional()
}).strict();

export const DocumentCreateOrConnectWithoutSignatureFieldInputSchema: z.ZodType<Prisma.DocumentCreateOrConnectWithoutSignatureFieldInput> = z.object({
  where: z.lazy(() => DocumentWhereUniqueInputSchema),
  create: z.union([ z.lazy(() => DocumentCreateWithoutSignatureFieldInputSchema),z.lazy(() => DocumentUncheckedCreateWithoutSignatureFieldInputSchema) ]),
}).strict();

export const DocumentSignerCreateWithoutSignatureFieldsInputSchema: z.ZodType<Prisma.DocumentSignerCreateWithoutSignatureFieldsInput> = z.object({
  id: z.string().uuid().optional(),
  email: z.string(),
  name: z.string().optional().nullable(),
  order: z.number().int(),
  status: z.lazy(() => SignerStatusSchema).optional(),
  expiresAt: z.coerce.date().optional().nullable(),
  notifiedAt: z.coerce.date().optional().nullable(),
  createdAt: z.coerce.date().optional(),
  updatedAt: z.coerce.date().optional(),
  document: z.lazy(() => DocumentCreateNestedOneWithoutSignersInputSchema),
  signature: z.lazy(() => SignatureCreateNestedOneWithoutDocumentSignerInputSchema).optional()
}).strict();

export const DocumentSignerUncheckedCreateWithoutSignatureFieldsInputSchema: z.ZodType<Prisma.DocumentSignerUncheckedCreateWithoutSignatureFieldsInput> = z.object({
  id: z.string().uuid().optional(),
  documentId: z.string(),
  email: z.string(),
  name: z.string().optional().nullable(),
  order: z.number().int(),
  status: z.lazy(() => SignerStatusSchema).optional(),
  expiresAt: z.coerce.date().optional().nullable(),
  notifiedAt: z.coerce.date().optional().nullable(),
  createdAt: z.coerce.date().optional(),
  updatedAt: z.coerce.date().optional(),
  signatureId: z.string().optional().nullable()
}).strict();

export const DocumentSignerCreateOrConnectWithoutSignatureFieldsInputSchema: z.ZodType<Prisma.DocumentSignerCreateOrConnectWithoutSignatureFieldsInput> = z.object({
  where: z.lazy(() => DocumentSignerWhereUniqueInputSchema),
  create: z.union([ z.lazy(() => DocumentSignerCreateWithoutSignatureFieldsInputSchema),z.lazy(() => DocumentSignerUncheckedCreateWithoutSignatureFieldsInputSchema) ]),
}).strict();

export const DocumentUpsertWithoutSignatureFieldInputSchema: z.ZodType<Prisma.DocumentUpsertWithoutSignatureFieldInput> = z.object({
  update: z.union([ z.lazy(() => DocumentUpdateWithoutSignatureFieldInputSchema),z.lazy(() => DocumentUncheckedUpdateWithoutSignatureFieldInputSchema) ]),
  create: z.union([ z.lazy(() => DocumentCreateWithoutSignatureFieldInputSchema),z.lazy(() => DocumentUncheckedCreateWithoutSignatureFieldInputSchema) ]),
  where: z.lazy(() => DocumentWhereInputSchema).optional()
}).strict();

export const DocumentUpdateToOneWithWhereWithoutSignatureFieldInputSchema: z.ZodType<Prisma.DocumentUpdateToOneWithWhereWithoutSignatureFieldInput> = z.object({
  where: z.lazy(() => DocumentWhereInputSchema).optional(),
  data: z.union([ z.lazy(() => DocumentUpdateWithoutSignatureFieldInputSchema),z.lazy(() => DocumentUncheckedUpdateWithoutSignatureFieldInputSchema) ]),
}).strict();

export const DocumentUpdateWithoutSignatureFieldInputSchema: z.ZodType<Prisma.DocumentUpdateWithoutSignatureFieldInput> = z.object({
  id: z.union([ z.string().uuid(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  title: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  description: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  status: z.union([ z.lazy(() => DocumentStatusSchema),z.lazy(() => EnumDocumentStatusFieldUpdateOperationsInputSchema) ]).optional(),
  fileUrl: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  fileHash: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  blockchainDocId: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  metadata: z.union([ z.lazy(() => NullableJsonNullValueInputSchema),InputJsonValueSchema ]).optional(),
  expiresAt: z.union([ z.coerce.date(),z.lazy(() => NullableDateTimeFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  createdAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  updatedAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  user: z.lazy(() => UserUpdateOneRequiredWithoutDocumentsNestedInputSchema).optional(),
  company: z.lazy(() => CompanyUpdateOneRequiredWithoutDocumentsNestedInputSchema).optional(),
  signingTemplate: z.lazy(() => SigningTemplateUpdateOneWithoutDocumentsNestedInputSchema).optional(),
  signers: z.lazy(() => DocumentSignerUpdateManyWithoutDocumentNestedInputSchema).optional(),
  signatures: z.lazy(() => SignatureUpdateManyWithoutDocumentNestedInputSchema).optional(),
  auditLogs: z.lazy(() => AuditLogUpdateManyWithoutDocumentNestedInputSchema).optional()
}).strict();

export const DocumentUncheckedUpdateWithoutSignatureFieldInputSchema: z.ZodType<Prisma.DocumentUncheckedUpdateWithoutSignatureFieldInput> = z.object({
  id: z.union([ z.string().uuid(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  title: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  description: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  userId: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  companyId: z.union([ z.number().int(),z.lazy(() => IntFieldUpdateOperationsInputSchema) ]).optional(),
  status: z.union([ z.lazy(() => DocumentStatusSchema),z.lazy(() => EnumDocumentStatusFieldUpdateOperationsInputSchema) ]).optional(),
  fileUrl: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  fileHash: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  blockchainDocId: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  templateId: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  metadata: z.union([ z.lazy(() => NullableJsonNullValueInputSchema),InputJsonValueSchema ]).optional(),
  expiresAt: z.union([ z.coerce.date(),z.lazy(() => NullableDateTimeFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  createdAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  updatedAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  signers: z.lazy(() => DocumentSignerUncheckedUpdateManyWithoutDocumentNestedInputSchema).optional(),
  signatures: z.lazy(() => SignatureUncheckedUpdateManyWithoutDocumentNestedInputSchema).optional(),
  auditLogs: z.lazy(() => AuditLogUncheckedUpdateManyWithoutDocumentNestedInputSchema).optional()
}).strict();

export const DocumentSignerUpsertWithoutSignatureFieldsInputSchema: z.ZodType<Prisma.DocumentSignerUpsertWithoutSignatureFieldsInput> = z.object({
  update: z.union([ z.lazy(() => DocumentSignerUpdateWithoutSignatureFieldsInputSchema),z.lazy(() => DocumentSignerUncheckedUpdateWithoutSignatureFieldsInputSchema) ]),
  create: z.union([ z.lazy(() => DocumentSignerCreateWithoutSignatureFieldsInputSchema),z.lazy(() => DocumentSignerUncheckedCreateWithoutSignatureFieldsInputSchema) ]),
  where: z.lazy(() => DocumentSignerWhereInputSchema).optional()
}).strict();

export const DocumentSignerUpdateToOneWithWhereWithoutSignatureFieldsInputSchema: z.ZodType<Prisma.DocumentSignerUpdateToOneWithWhereWithoutSignatureFieldsInput> = z.object({
  where: z.lazy(() => DocumentSignerWhereInputSchema).optional(),
  data: z.union([ z.lazy(() => DocumentSignerUpdateWithoutSignatureFieldsInputSchema),z.lazy(() => DocumentSignerUncheckedUpdateWithoutSignatureFieldsInputSchema) ]),
}).strict();

export const DocumentSignerUpdateWithoutSignatureFieldsInputSchema: z.ZodType<Prisma.DocumentSignerUpdateWithoutSignatureFieldsInput> = z.object({
  id: z.union([ z.string().uuid(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  email: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  name: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  order: z.union([ z.number().int(),z.lazy(() => IntFieldUpdateOperationsInputSchema) ]).optional(),
  status: z.union([ z.lazy(() => SignerStatusSchema),z.lazy(() => EnumSignerStatusFieldUpdateOperationsInputSchema) ]).optional(),
  expiresAt: z.union([ z.coerce.date(),z.lazy(() => NullableDateTimeFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  notifiedAt: z.union([ z.coerce.date(),z.lazy(() => NullableDateTimeFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  createdAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  updatedAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  document: z.lazy(() => DocumentUpdateOneRequiredWithoutSignersNestedInputSchema).optional(),
  signature: z.lazy(() => SignatureUpdateOneWithoutDocumentSignerNestedInputSchema).optional()
}).strict();

export const DocumentSignerUncheckedUpdateWithoutSignatureFieldsInputSchema: z.ZodType<Prisma.DocumentSignerUncheckedUpdateWithoutSignatureFieldsInput> = z.object({
  id: z.union([ z.string().uuid(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  documentId: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  email: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  name: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  order: z.union([ z.number().int(),z.lazy(() => IntFieldUpdateOperationsInputSchema) ]).optional(),
  status: z.union([ z.lazy(() => SignerStatusSchema),z.lazy(() => EnumSignerStatusFieldUpdateOperationsInputSchema) ]).optional(),
  expiresAt: z.union([ z.coerce.date(),z.lazy(() => NullableDateTimeFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  notifiedAt: z.union([ z.coerce.date(),z.lazy(() => NullableDateTimeFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  createdAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  updatedAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  signatureId: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
}).strict();

export const DocumentCreateWithoutSignaturesInputSchema: z.ZodType<Prisma.DocumentCreateWithoutSignaturesInput> = z.object({
  id: z.string().uuid().optional(),
  title: z.string().optional().nullable(),
  description: z.string().optional().nullable(),
  status: z.lazy(() => DocumentStatusSchema).optional(),
  fileUrl: z.string(),
  fileHash: z.string().optional().nullable(),
  blockchainDocId: z.string().optional().nullable(),
  metadata: z.union([ z.lazy(() => NullableJsonNullValueInputSchema),InputJsonValueSchema ]).optional(),
  expiresAt: z.coerce.date().optional().nullable(),
  createdAt: z.coerce.date().optional(),
  updatedAt: z.coerce.date().optional(),
  user: z.lazy(() => UserCreateNestedOneWithoutDocumentsInputSchema),
  company: z.lazy(() => CompanyCreateNestedOneWithoutDocumentsInputSchema),
  signingTemplate: z.lazy(() => SigningTemplateCreateNestedOneWithoutDocumentsInputSchema).optional(),
  signers: z.lazy(() => DocumentSignerCreateNestedManyWithoutDocumentInputSchema).optional(),
  auditLogs: z.lazy(() => AuditLogCreateNestedManyWithoutDocumentInputSchema).optional(),
  SignatureField: z.lazy(() => SignatureFieldCreateNestedManyWithoutDocumentInputSchema).optional()
}).strict();

export const DocumentUncheckedCreateWithoutSignaturesInputSchema: z.ZodType<Prisma.DocumentUncheckedCreateWithoutSignaturesInput> = z.object({
  id: z.string().uuid().optional(),
  title: z.string().optional().nullable(),
  description: z.string().optional().nullable(),
  userId: z.string(),
  companyId: z.number().int(),
  status: z.lazy(() => DocumentStatusSchema).optional(),
  fileUrl: z.string(),
  fileHash: z.string().optional().nullable(),
  blockchainDocId: z.string().optional().nullable(),
  templateId: z.string().optional().nullable(),
  metadata: z.union([ z.lazy(() => NullableJsonNullValueInputSchema),InputJsonValueSchema ]).optional(),
  expiresAt: z.coerce.date().optional().nullable(),
  createdAt: z.coerce.date().optional(),
  updatedAt: z.coerce.date().optional(),
  signers: z.lazy(() => DocumentSignerUncheckedCreateNestedManyWithoutDocumentInputSchema).optional(),
  auditLogs: z.lazy(() => AuditLogUncheckedCreateNestedManyWithoutDocumentInputSchema).optional(),
  SignatureField: z.lazy(() => SignatureFieldUncheckedCreateNestedManyWithoutDocumentInputSchema).optional()
}).strict();

export const DocumentCreateOrConnectWithoutSignaturesInputSchema: z.ZodType<Prisma.DocumentCreateOrConnectWithoutSignaturesInput> = z.object({
  where: z.lazy(() => DocumentWhereUniqueInputSchema),
  create: z.union([ z.lazy(() => DocumentCreateWithoutSignaturesInputSchema),z.lazy(() => DocumentUncheckedCreateWithoutSignaturesInputSchema) ]),
}).strict();

export const UserCreateWithoutSignaturesInputSchema: z.ZodType<Prisma.UserCreateWithoutSignaturesInput> = z.object({
  id: z.string().uuid().optional(),
  email: z.string(),
  name: z.string(),
  role: z.lazy(() => UserRoleSchema).optional(),
  createdAt: z.coerce.date().optional(),
  updatedAt: z.coerce.date().optional(),
  company: z.lazy(() => CompanyCreateNestedOneWithoutUsersInputSchema),
  documents: z.lazy(() => DocumentCreateNestedManyWithoutUserInputSchema).optional(),
  apiKeys: z.lazy(() => ApiKeyCreateNestedManyWithoutUserInputSchema).optional()
}).strict();

export const UserUncheckedCreateWithoutSignaturesInputSchema: z.ZodType<Prisma.UserUncheckedCreateWithoutSignaturesInput> = z.object({
  id: z.string().uuid().optional(),
  email: z.string(),
  name: z.string(),
  companyId: z.number().int(),
  role: z.lazy(() => UserRoleSchema).optional(),
  createdAt: z.coerce.date().optional(),
  updatedAt: z.coerce.date().optional(),
  documents: z.lazy(() => DocumentUncheckedCreateNestedManyWithoutUserInputSchema).optional(),
  apiKeys: z.lazy(() => ApiKeyUncheckedCreateNestedManyWithoutUserInputSchema).optional()
}).strict();

export const UserCreateOrConnectWithoutSignaturesInputSchema: z.ZodType<Prisma.UserCreateOrConnectWithoutSignaturesInput> = z.object({
  where: z.lazy(() => UserWhereUniqueInputSchema),
  create: z.union([ z.lazy(() => UserCreateWithoutSignaturesInputSchema),z.lazy(() => UserUncheckedCreateWithoutSignaturesInputSchema) ]),
}).strict();

export const CertificateCreateWithoutSignaturesInputSchema: z.ZodType<Prisma.CertificateCreateWithoutSignaturesInput> = z.object({
  id: z.string().uuid().optional(),
  fingerprint: z.string(),
  publicKey: z.string(),
  privateKey: z.string().optional().nullable(),
  isCA: z.boolean().optional(),
  issuerCertId: z.string().optional().nullable(),
  validFrom: z.coerce.date(),
  validTo: z.coerce.date(),
  metadata: z.union([ z.lazy(() => NullableJsonNullValueInputSchema),InputJsonValueSchema ]).optional(),
  createdAt: z.coerce.date().optional(),
  updatedAt: z.coerce.date().optional(),
  company: z.lazy(() => CompanyCreateNestedOneWithoutCertificatesInputSchema)
}).strict();

export const CertificateUncheckedCreateWithoutSignaturesInputSchema: z.ZodType<Prisma.CertificateUncheckedCreateWithoutSignaturesInput> = z.object({
  id: z.string().uuid().optional(),
  companyId: z.number().int(),
  fingerprint: z.string(),
  publicKey: z.string(),
  privateKey: z.string().optional().nullable(),
  isCA: z.boolean().optional(),
  issuerCertId: z.string().optional().nullable(),
  validFrom: z.coerce.date(),
  validTo: z.coerce.date(),
  metadata: z.union([ z.lazy(() => NullableJsonNullValueInputSchema),InputJsonValueSchema ]).optional(),
  createdAt: z.coerce.date().optional(),
  updatedAt: z.coerce.date().optional()
}).strict();

export const CertificateCreateOrConnectWithoutSignaturesInputSchema: z.ZodType<Prisma.CertificateCreateOrConnectWithoutSignaturesInput> = z.object({
  where: z.lazy(() => CertificateWhereUniqueInputSchema),
  create: z.union([ z.lazy(() => CertificateCreateWithoutSignaturesInputSchema),z.lazy(() => CertificateUncheckedCreateWithoutSignaturesInputSchema) ]),
}).strict();

export const DocumentSignerCreateWithoutSignatureInputSchema: z.ZodType<Prisma.DocumentSignerCreateWithoutSignatureInput> = z.object({
  id: z.string().uuid().optional(),
  email: z.string(),
  name: z.string().optional().nullable(),
  order: z.number().int(),
  status: z.lazy(() => SignerStatusSchema).optional(),
  expiresAt: z.coerce.date().optional().nullable(),
  notifiedAt: z.coerce.date().optional().nullable(),
  createdAt: z.coerce.date().optional(),
  updatedAt: z.coerce.date().optional(),
  document: z.lazy(() => DocumentCreateNestedOneWithoutSignersInputSchema),
  signatureFields: z.lazy(() => SignatureFieldCreateNestedManyWithoutSignerInputSchema).optional()
}).strict();

export const DocumentSignerUncheckedCreateWithoutSignatureInputSchema: z.ZodType<Prisma.DocumentSignerUncheckedCreateWithoutSignatureInput> = z.object({
  id: z.string().uuid().optional(),
  documentId: z.string(),
  email: z.string(),
  name: z.string().optional().nullable(),
  order: z.number().int(),
  status: z.lazy(() => SignerStatusSchema).optional(),
  expiresAt: z.coerce.date().optional().nullable(),
  notifiedAt: z.coerce.date().optional().nullable(),
  createdAt: z.coerce.date().optional(),
  updatedAt: z.coerce.date().optional(),
  signatureFields: z.lazy(() => SignatureFieldUncheckedCreateNestedManyWithoutSignerInputSchema).optional()
}).strict();

export const DocumentSignerCreateOrConnectWithoutSignatureInputSchema: z.ZodType<Prisma.DocumentSignerCreateOrConnectWithoutSignatureInput> = z.object({
  where: z.lazy(() => DocumentSignerWhereUniqueInputSchema),
  create: z.union([ z.lazy(() => DocumentSignerCreateWithoutSignatureInputSchema),z.lazy(() => DocumentSignerUncheckedCreateWithoutSignatureInputSchema) ]),
}).strict();

export const DocumentSignerCreateManySignatureInputEnvelopeSchema: z.ZodType<Prisma.DocumentSignerCreateManySignatureInputEnvelope> = z.object({
  data: z.union([ z.lazy(() => DocumentSignerCreateManySignatureInputSchema),z.lazy(() => DocumentSignerCreateManySignatureInputSchema).array() ]),
  skipDuplicates: z.boolean().optional()
}).strict();

export const DocumentUpsertWithoutSignaturesInputSchema: z.ZodType<Prisma.DocumentUpsertWithoutSignaturesInput> = z.object({
  update: z.union([ z.lazy(() => DocumentUpdateWithoutSignaturesInputSchema),z.lazy(() => DocumentUncheckedUpdateWithoutSignaturesInputSchema) ]),
  create: z.union([ z.lazy(() => DocumentCreateWithoutSignaturesInputSchema),z.lazy(() => DocumentUncheckedCreateWithoutSignaturesInputSchema) ]),
  where: z.lazy(() => DocumentWhereInputSchema).optional()
}).strict();

export const DocumentUpdateToOneWithWhereWithoutSignaturesInputSchema: z.ZodType<Prisma.DocumentUpdateToOneWithWhereWithoutSignaturesInput> = z.object({
  where: z.lazy(() => DocumentWhereInputSchema).optional(),
  data: z.union([ z.lazy(() => DocumentUpdateWithoutSignaturesInputSchema),z.lazy(() => DocumentUncheckedUpdateWithoutSignaturesInputSchema) ]),
}).strict();

export const DocumentUpdateWithoutSignaturesInputSchema: z.ZodType<Prisma.DocumentUpdateWithoutSignaturesInput> = z.object({
  id: z.union([ z.string().uuid(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  title: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  description: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  status: z.union([ z.lazy(() => DocumentStatusSchema),z.lazy(() => EnumDocumentStatusFieldUpdateOperationsInputSchema) ]).optional(),
  fileUrl: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  fileHash: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  blockchainDocId: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  metadata: z.union([ z.lazy(() => NullableJsonNullValueInputSchema),InputJsonValueSchema ]).optional(),
  expiresAt: z.union([ z.coerce.date(),z.lazy(() => NullableDateTimeFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  createdAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  updatedAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  user: z.lazy(() => UserUpdateOneRequiredWithoutDocumentsNestedInputSchema).optional(),
  company: z.lazy(() => CompanyUpdateOneRequiredWithoutDocumentsNestedInputSchema).optional(),
  signingTemplate: z.lazy(() => SigningTemplateUpdateOneWithoutDocumentsNestedInputSchema).optional(),
  signers: z.lazy(() => DocumentSignerUpdateManyWithoutDocumentNestedInputSchema).optional(),
  auditLogs: z.lazy(() => AuditLogUpdateManyWithoutDocumentNestedInputSchema).optional(),
  SignatureField: z.lazy(() => SignatureFieldUpdateManyWithoutDocumentNestedInputSchema).optional()
}).strict();

export const DocumentUncheckedUpdateWithoutSignaturesInputSchema: z.ZodType<Prisma.DocumentUncheckedUpdateWithoutSignaturesInput> = z.object({
  id: z.union([ z.string().uuid(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  title: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  description: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  userId: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  companyId: z.union([ z.number().int(),z.lazy(() => IntFieldUpdateOperationsInputSchema) ]).optional(),
  status: z.union([ z.lazy(() => DocumentStatusSchema),z.lazy(() => EnumDocumentStatusFieldUpdateOperationsInputSchema) ]).optional(),
  fileUrl: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  fileHash: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  blockchainDocId: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  templateId: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  metadata: z.union([ z.lazy(() => NullableJsonNullValueInputSchema),InputJsonValueSchema ]).optional(),
  expiresAt: z.union([ z.coerce.date(),z.lazy(() => NullableDateTimeFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  createdAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  updatedAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  signers: z.lazy(() => DocumentSignerUncheckedUpdateManyWithoutDocumentNestedInputSchema).optional(),
  auditLogs: z.lazy(() => AuditLogUncheckedUpdateManyWithoutDocumentNestedInputSchema).optional(),
  SignatureField: z.lazy(() => SignatureFieldUncheckedUpdateManyWithoutDocumentNestedInputSchema).optional()
}).strict();

export const UserUpsertWithoutSignaturesInputSchema: z.ZodType<Prisma.UserUpsertWithoutSignaturesInput> = z.object({
  update: z.union([ z.lazy(() => UserUpdateWithoutSignaturesInputSchema),z.lazy(() => UserUncheckedUpdateWithoutSignaturesInputSchema) ]),
  create: z.union([ z.lazy(() => UserCreateWithoutSignaturesInputSchema),z.lazy(() => UserUncheckedCreateWithoutSignaturesInputSchema) ]),
  where: z.lazy(() => UserWhereInputSchema).optional()
}).strict();

export const UserUpdateToOneWithWhereWithoutSignaturesInputSchema: z.ZodType<Prisma.UserUpdateToOneWithWhereWithoutSignaturesInput> = z.object({
  where: z.lazy(() => UserWhereInputSchema).optional(),
  data: z.union([ z.lazy(() => UserUpdateWithoutSignaturesInputSchema),z.lazy(() => UserUncheckedUpdateWithoutSignaturesInputSchema) ]),
}).strict();

export const UserUpdateWithoutSignaturesInputSchema: z.ZodType<Prisma.UserUpdateWithoutSignaturesInput> = z.object({
  id: z.union([ z.string().uuid(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  email: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  name: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  role: z.union([ z.lazy(() => UserRoleSchema),z.lazy(() => EnumUserRoleFieldUpdateOperationsInputSchema) ]).optional(),
  createdAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  updatedAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  company: z.lazy(() => CompanyUpdateOneRequiredWithoutUsersNestedInputSchema).optional(),
  documents: z.lazy(() => DocumentUpdateManyWithoutUserNestedInputSchema).optional(),
  apiKeys: z.lazy(() => ApiKeyUpdateManyWithoutUserNestedInputSchema).optional()
}).strict();

export const UserUncheckedUpdateWithoutSignaturesInputSchema: z.ZodType<Prisma.UserUncheckedUpdateWithoutSignaturesInput> = z.object({
  id: z.union([ z.string().uuid(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  email: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  name: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  companyId: z.union([ z.number().int(),z.lazy(() => IntFieldUpdateOperationsInputSchema) ]).optional(),
  role: z.union([ z.lazy(() => UserRoleSchema),z.lazy(() => EnumUserRoleFieldUpdateOperationsInputSchema) ]).optional(),
  createdAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  updatedAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  documents: z.lazy(() => DocumentUncheckedUpdateManyWithoutUserNestedInputSchema).optional(),
  apiKeys: z.lazy(() => ApiKeyUncheckedUpdateManyWithoutUserNestedInputSchema).optional()
}).strict();

export const CertificateUpsertWithoutSignaturesInputSchema: z.ZodType<Prisma.CertificateUpsertWithoutSignaturesInput> = z.object({
  update: z.union([ z.lazy(() => CertificateUpdateWithoutSignaturesInputSchema),z.lazy(() => CertificateUncheckedUpdateWithoutSignaturesInputSchema) ]),
  create: z.union([ z.lazy(() => CertificateCreateWithoutSignaturesInputSchema),z.lazy(() => CertificateUncheckedCreateWithoutSignaturesInputSchema) ]),
  where: z.lazy(() => CertificateWhereInputSchema).optional()
}).strict();

export const CertificateUpdateToOneWithWhereWithoutSignaturesInputSchema: z.ZodType<Prisma.CertificateUpdateToOneWithWhereWithoutSignaturesInput> = z.object({
  where: z.lazy(() => CertificateWhereInputSchema).optional(),
  data: z.union([ z.lazy(() => CertificateUpdateWithoutSignaturesInputSchema),z.lazy(() => CertificateUncheckedUpdateWithoutSignaturesInputSchema) ]),
}).strict();

export const CertificateUpdateWithoutSignaturesInputSchema: z.ZodType<Prisma.CertificateUpdateWithoutSignaturesInput> = z.object({
  id: z.union([ z.string().uuid(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  fingerprint: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  publicKey: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  privateKey: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  isCA: z.union([ z.boolean(),z.lazy(() => BoolFieldUpdateOperationsInputSchema) ]).optional(),
  issuerCertId: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  validFrom: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  validTo: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  metadata: z.union([ z.lazy(() => NullableJsonNullValueInputSchema),InputJsonValueSchema ]).optional(),
  createdAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  updatedAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  company: z.lazy(() => CompanyUpdateOneRequiredWithoutCertificatesNestedInputSchema).optional()
}).strict();

export const CertificateUncheckedUpdateWithoutSignaturesInputSchema: z.ZodType<Prisma.CertificateUncheckedUpdateWithoutSignaturesInput> = z.object({
  id: z.union([ z.string().uuid(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  companyId: z.union([ z.number().int(),z.lazy(() => IntFieldUpdateOperationsInputSchema) ]).optional(),
  fingerprint: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  publicKey: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  privateKey: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  isCA: z.union([ z.boolean(),z.lazy(() => BoolFieldUpdateOperationsInputSchema) ]).optional(),
  issuerCertId: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  validFrom: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  validTo: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  metadata: z.union([ z.lazy(() => NullableJsonNullValueInputSchema),InputJsonValueSchema ]).optional(),
  createdAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  updatedAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
}).strict();

export const DocumentSignerUpsertWithWhereUniqueWithoutSignatureInputSchema: z.ZodType<Prisma.DocumentSignerUpsertWithWhereUniqueWithoutSignatureInput> = z.object({
  where: z.lazy(() => DocumentSignerWhereUniqueInputSchema),
  update: z.union([ z.lazy(() => DocumentSignerUpdateWithoutSignatureInputSchema),z.lazy(() => DocumentSignerUncheckedUpdateWithoutSignatureInputSchema) ]),
  create: z.union([ z.lazy(() => DocumentSignerCreateWithoutSignatureInputSchema),z.lazy(() => DocumentSignerUncheckedCreateWithoutSignatureInputSchema) ]),
}).strict();

export const DocumentSignerUpdateWithWhereUniqueWithoutSignatureInputSchema: z.ZodType<Prisma.DocumentSignerUpdateWithWhereUniqueWithoutSignatureInput> = z.object({
  where: z.lazy(() => DocumentSignerWhereUniqueInputSchema),
  data: z.union([ z.lazy(() => DocumentSignerUpdateWithoutSignatureInputSchema),z.lazy(() => DocumentSignerUncheckedUpdateWithoutSignatureInputSchema) ]),
}).strict();

export const DocumentSignerUpdateManyWithWhereWithoutSignatureInputSchema: z.ZodType<Prisma.DocumentSignerUpdateManyWithWhereWithoutSignatureInput> = z.object({
  where: z.lazy(() => DocumentSignerScalarWhereInputSchema),
  data: z.union([ z.lazy(() => DocumentSignerUpdateManyMutationInputSchema),z.lazy(() => DocumentSignerUncheckedUpdateManyWithoutSignatureInputSchema) ]),
}).strict();

export const CompanyCreateWithoutCertificatesInputSchema: z.ZodType<Prisma.CompanyCreateWithoutCertificatesInput> = z.object({
  id: z.number().int(),
  name: z.string(),
  adminEmail: z.string(),
  country: z.string(),
  rootCertificate: z.string().optional().nullable(),
  subscriptionId: z.string().optional().nullable(),
  createdAt: z.coerce.date().optional(),
  updatedAt: z.coerce.date().optional(),
  users: z.lazy(() => UserCreateNestedManyWithoutCompanyInputSchema).optional(),
  documents: z.lazy(() => DocumentCreateNestedManyWithoutCompanyInputSchema).optional(),
  blockchainWallet: z.lazy(() => BlockchainWalletCreateNestedOneWithoutCompanyInputSchema).optional(),
  SigningTemplate: z.lazy(() => SigningTemplateCreateNestedManyWithoutCompanyInputSchema).optional(),
  ApiKey: z.lazy(() => ApiKeyCreateNestedManyWithoutCompanyInputSchema).optional()
}).strict();

export const CompanyUncheckedCreateWithoutCertificatesInputSchema: z.ZodType<Prisma.CompanyUncheckedCreateWithoutCertificatesInput> = z.object({
  id: z.number().int(),
  name: z.string(),
  adminEmail: z.string(),
  country: z.string(),
  rootCertificate: z.string().optional().nullable(),
  subscriptionId: z.string().optional().nullable(),
  createdAt: z.coerce.date().optional(),
  updatedAt: z.coerce.date().optional(),
  users: z.lazy(() => UserUncheckedCreateNestedManyWithoutCompanyInputSchema).optional(),
  documents: z.lazy(() => DocumentUncheckedCreateNestedManyWithoutCompanyInputSchema).optional(),
  blockchainWallet: z.lazy(() => BlockchainWalletUncheckedCreateNestedOneWithoutCompanyInputSchema).optional(),
  SigningTemplate: z.lazy(() => SigningTemplateUncheckedCreateNestedManyWithoutCompanyInputSchema).optional(),
  ApiKey: z.lazy(() => ApiKeyUncheckedCreateNestedManyWithoutCompanyInputSchema).optional()
}).strict();

export const CompanyCreateOrConnectWithoutCertificatesInputSchema: z.ZodType<Prisma.CompanyCreateOrConnectWithoutCertificatesInput> = z.object({
  where: z.lazy(() => CompanyWhereUniqueInputSchema),
  create: z.union([ z.lazy(() => CompanyCreateWithoutCertificatesInputSchema),z.lazy(() => CompanyUncheckedCreateWithoutCertificatesInputSchema) ]),
}).strict();

export const SignatureCreateWithoutCertificateInputSchema: z.ZodType<Prisma.SignatureCreateWithoutCertificateInput> = z.object({
  id: z.string().uuid().optional(),
  signatureData: z.string(),
  visualSignature: z.string().optional().nullable(),
  blockchainTx: z.string().optional().nullable(),
  coordinates: z.union([ z.lazy(() => NullableJsonNullValueInputSchema),InputJsonValueSchema ]).optional(),
  metadata: z.union([ z.lazy(() => NullableJsonNullValueInputSchema),InputJsonValueSchema ]).optional(),
  createdAt: z.coerce.date().optional(),
  updatedAt: z.coerce.date().optional(),
  document: z.lazy(() => DocumentCreateNestedOneWithoutSignaturesInputSchema),
  user: z.lazy(() => UserCreateNestedOneWithoutSignaturesInputSchema),
  DocumentSigner: z.lazy(() => DocumentSignerCreateNestedManyWithoutSignatureInputSchema).optional()
}).strict();

export const SignatureUncheckedCreateWithoutCertificateInputSchema: z.ZodType<Prisma.SignatureUncheckedCreateWithoutCertificateInput> = z.object({
  id: z.string().uuid().optional(),
  documentId: z.string(),
  userId: z.string(),
  signatureData: z.string(),
  visualSignature: z.string().optional().nullable(),
  blockchainTx: z.string().optional().nullable(),
  coordinates: z.union([ z.lazy(() => NullableJsonNullValueInputSchema),InputJsonValueSchema ]).optional(),
  metadata: z.union([ z.lazy(() => NullableJsonNullValueInputSchema),InputJsonValueSchema ]).optional(),
  createdAt: z.coerce.date().optional(),
  updatedAt: z.coerce.date().optional(),
  DocumentSigner: z.lazy(() => DocumentSignerUncheckedCreateNestedManyWithoutSignatureInputSchema).optional()
}).strict();

export const SignatureCreateOrConnectWithoutCertificateInputSchema: z.ZodType<Prisma.SignatureCreateOrConnectWithoutCertificateInput> = z.object({
  where: z.lazy(() => SignatureWhereUniqueInputSchema),
  create: z.union([ z.lazy(() => SignatureCreateWithoutCertificateInputSchema),z.lazy(() => SignatureUncheckedCreateWithoutCertificateInputSchema) ]),
}).strict();

export const SignatureCreateManyCertificateInputEnvelopeSchema: z.ZodType<Prisma.SignatureCreateManyCertificateInputEnvelope> = z.object({
  data: z.union([ z.lazy(() => SignatureCreateManyCertificateInputSchema),z.lazy(() => SignatureCreateManyCertificateInputSchema).array() ]),
  skipDuplicates: z.boolean().optional()
}).strict();

export const CompanyUpsertWithoutCertificatesInputSchema: z.ZodType<Prisma.CompanyUpsertWithoutCertificatesInput> = z.object({
  update: z.union([ z.lazy(() => CompanyUpdateWithoutCertificatesInputSchema),z.lazy(() => CompanyUncheckedUpdateWithoutCertificatesInputSchema) ]),
  create: z.union([ z.lazy(() => CompanyCreateWithoutCertificatesInputSchema),z.lazy(() => CompanyUncheckedCreateWithoutCertificatesInputSchema) ]),
  where: z.lazy(() => CompanyWhereInputSchema).optional()
}).strict();

export const CompanyUpdateToOneWithWhereWithoutCertificatesInputSchema: z.ZodType<Prisma.CompanyUpdateToOneWithWhereWithoutCertificatesInput> = z.object({
  where: z.lazy(() => CompanyWhereInputSchema).optional(),
  data: z.union([ z.lazy(() => CompanyUpdateWithoutCertificatesInputSchema),z.lazy(() => CompanyUncheckedUpdateWithoutCertificatesInputSchema) ]),
}).strict();

export const CompanyUpdateWithoutCertificatesInputSchema: z.ZodType<Prisma.CompanyUpdateWithoutCertificatesInput> = z.object({
  id: z.union([ z.number().int(),z.lazy(() => IntFieldUpdateOperationsInputSchema) ]).optional(),
  name: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  adminEmail: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  country: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  rootCertificate: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  subscriptionId: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  createdAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  updatedAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  users: z.lazy(() => UserUpdateManyWithoutCompanyNestedInputSchema).optional(),
  documents: z.lazy(() => DocumentUpdateManyWithoutCompanyNestedInputSchema).optional(),
  blockchainWallet: z.lazy(() => BlockchainWalletUpdateOneWithoutCompanyNestedInputSchema).optional(),
  SigningTemplate: z.lazy(() => SigningTemplateUpdateManyWithoutCompanyNestedInputSchema).optional(),
  ApiKey: z.lazy(() => ApiKeyUpdateManyWithoutCompanyNestedInputSchema).optional()
}).strict();

export const CompanyUncheckedUpdateWithoutCertificatesInputSchema: z.ZodType<Prisma.CompanyUncheckedUpdateWithoutCertificatesInput> = z.object({
  id: z.union([ z.number().int(),z.lazy(() => IntFieldUpdateOperationsInputSchema) ]).optional(),
  name: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  adminEmail: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  country: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  rootCertificate: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  subscriptionId: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  createdAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  updatedAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  users: z.lazy(() => UserUncheckedUpdateManyWithoutCompanyNestedInputSchema).optional(),
  documents: z.lazy(() => DocumentUncheckedUpdateManyWithoutCompanyNestedInputSchema).optional(),
  blockchainWallet: z.lazy(() => BlockchainWalletUncheckedUpdateOneWithoutCompanyNestedInputSchema).optional(),
  SigningTemplate: z.lazy(() => SigningTemplateUncheckedUpdateManyWithoutCompanyNestedInputSchema).optional(),
  ApiKey: z.lazy(() => ApiKeyUncheckedUpdateManyWithoutCompanyNestedInputSchema).optional()
}).strict();

export const SignatureUpsertWithWhereUniqueWithoutCertificateInputSchema: z.ZodType<Prisma.SignatureUpsertWithWhereUniqueWithoutCertificateInput> = z.object({
  where: z.lazy(() => SignatureWhereUniqueInputSchema),
  update: z.union([ z.lazy(() => SignatureUpdateWithoutCertificateInputSchema),z.lazy(() => SignatureUncheckedUpdateWithoutCertificateInputSchema) ]),
  create: z.union([ z.lazy(() => SignatureCreateWithoutCertificateInputSchema),z.lazy(() => SignatureUncheckedCreateWithoutCertificateInputSchema) ]),
}).strict();

export const SignatureUpdateWithWhereUniqueWithoutCertificateInputSchema: z.ZodType<Prisma.SignatureUpdateWithWhereUniqueWithoutCertificateInput> = z.object({
  where: z.lazy(() => SignatureWhereUniqueInputSchema),
  data: z.union([ z.lazy(() => SignatureUpdateWithoutCertificateInputSchema),z.lazy(() => SignatureUncheckedUpdateWithoutCertificateInputSchema) ]),
}).strict();

export const SignatureUpdateManyWithWhereWithoutCertificateInputSchema: z.ZodType<Prisma.SignatureUpdateManyWithWhereWithoutCertificateInput> = z.object({
  where: z.lazy(() => SignatureScalarWhereInputSchema),
  data: z.union([ z.lazy(() => SignatureUpdateManyMutationInputSchema),z.lazy(() => SignatureUncheckedUpdateManyWithoutCertificateInputSchema) ]),
}).strict();

export const CompanyCreateWithoutSigningTemplateInputSchema: z.ZodType<Prisma.CompanyCreateWithoutSigningTemplateInput> = z.object({
  id: z.number().int(),
  name: z.string(),
  adminEmail: z.string(),
  country: z.string(),
  rootCertificate: z.string().optional().nullable(),
  subscriptionId: z.string().optional().nullable(),
  createdAt: z.coerce.date().optional(),
  updatedAt: z.coerce.date().optional(),
  users: z.lazy(() => UserCreateNestedManyWithoutCompanyInputSchema).optional(),
  documents: z.lazy(() => DocumentCreateNestedManyWithoutCompanyInputSchema).optional(),
  certificates: z.lazy(() => CertificateCreateNestedManyWithoutCompanyInputSchema).optional(),
  blockchainWallet: z.lazy(() => BlockchainWalletCreateNestedOneWithoutCompanyInputSchema).optional(),
  ApiKey: z.lazy(() => ApiKeyCreateNestedManyWithoutCompanyInputSchema).optional()
}).strict();

export const CompanyUncheckedCreateWithoutSigningTemplateInputSchema: z.ZodType<Prisma.CompanyUncheckedCreateWithoutSigningTemplateInput> = z.object({
  id: z.number().int(),
  name: z.string(),
  adminEmail: z.string(),
  country: z.string(),
  rootCertificate: z.string().optional().nullable(),
  subscriptionId: z.string().optional().nullable(),
  createdAt: z.coerce.date().optional(),
  updatedAt: z.coerce.date().optional(),
  users: z.lazy(() => UserUncheckedCreateNestedManyWithoutCompanyInputSchema).optional(),
  documents: z.lazy(() => DocumentUncheckedCreateNestedManyWithoutCompanyInputSchema).optional(),
  certificates: z.lazy(() => CertificateUncheckedCreateNestedManyWithoutCompanyInputSchema).optional(),
  blockchainWallet: z.lazy(() => BlockchainWalletUncheckedCreateNestedOneWithoutCompanyInputSchema).optional(),
  ApiKey: z.lazy(() => ApiKeyUncheckedCreateNestedManyWithoutCompanyInputSchema).optional()
}).strict();

export const CompanyCreateOrConnectWithoutSigningTemplateInputSchema: z.ZodType<Prisma.CompanyCreateOrConnectWithoutSigningTemplateInput> = z.object({
  where: z.lazy(() => CompanyWhereUniqueInputSchema),
  create: z.union([ z.lazy(() => CompanyCreateWithoutSigningTemplateInputSchema),z.lazy(() => CompanyUncheckedCreateWithoutSigningTemplateInputSchema) ]),
}).strict();

export const DocumentCreateWithoutSigningTemplateInputSchema: z.ZodType<Prisma.DocumentCreateWithoutSigningTemplateInput> = z.object({
  id: z.string().uuid().optional(),
  title: z.string().optional().nullable(),
  description: z.string().optional().nullable(),
  status: z.lazy(() => DocumentStatusSchema).optional(),
  fileUrl: z.string(),
  fileHash: z.string().optional().nullable(),
  blockchainDocId: z.string().optional().nullable(),
  metadata: z.union([ z.lazy(() => NullableJsonNullValueInputSchema),InputJsonValueSchema ]).optional(),
  expiresAt: z.coerce.date().optional().nullable(),
  createdAt: z.coerce.date().optional(),
  updatedAt: z.coerce.date().optional(),
  user: z.lazy(() => UserCreateNestedOneWithoutDocumentsInputSchema),
  company: z.lazy(() => CompanyCreateNestedOneWithoutDocumentsInputSchema),
  signers: z.lazy(() => DocumentSignerCreateNestedManyWithoutDocumentInputSchema).optional(),
  signatures: z.lazy(() => SignatureCreateNestedManyWithoutDocumentInputSchema).optional(),
  auditLogs: z.lazy(() => AuditLogCreateNestedManyWithoutDocumentInputSchema).optional(),
  SignatureField: z.lazy(() => SignatureFieldCreateNestedManyWithoutDocumentInputSchema).optional()
}).strict();

export const DocumentUncheckedCreateWithoutSigningTemplateInputSchema: z.ZodType<Prisma.DocumentUncheckedCreateWithoutSigningTemplateInput> = z.object({
  id: z.string().uuid().optional(),
  title: z.string().optional().nullable(),
  description: z.string().optional().nullable(),
  userId: z.string(),
  companyId: z.number().int(),
  status: z.lazy(() => DocumentStatusSchema).optional(),
  fileUrl: z.string(),
  fileHash: z.string().optional().nullable(),
  blockchainDocId: z.string().optional().nullable(),
  metadata: z.union([ z.lazy(() => NullableJsonNullValueInputSchema),InputJsonValueSchema ]).optional(),
  expiresAt: z.coerce.date().optional().nullable(),
  createdAt: z.coerce.date().optional(),
  updatedAt: z.coerce.date().optional(),
  signers: z.lazy(() => DocumentSignerUncheckedCreateNestedManyWithoutDocumentInputSchema).optional(),
  signatures: z.lazy(() => SignatureUncheckedCreateNestedManyWithoutDocumentInputSchema).optional(),
  auditLogs: z.lazy(() => AuditLogUncheckedCreateNestedManyWithoutDocumentInputSchema).optional(),
  SignatureField: z.lazy(() => SignatureFieldUncheckedCreateNestedManyWithoutDocumentInputSchema).optional()
}).strict();

export const DocumentCreateOrConnectWithoutSigningTemplateInputSchema: z.ZodType<Prisma.DocumentCreateOrConnectWithoutSigningTemplateInput> = z.object({
  where: z.lazy(() => DocumentWhereUniqueInputSchema),
  create: z.union([ z.lazy(() => DocumentCreateWithoutSigningTemplateInputSchema),z.lazy(() => DocumentUncheckedCreateWithoutSigningTemplateInputSchema) ]),
}).strict();

export const DocumentCreateManySigningTemplateInputEnvelopeSchema: z.ZodType<Prisma.DocumentCreateManySigningTemplateInputEnvelope> = z.object({
  data: z.union([ z.lazy(() => DocumentCreateManySigningTemplateInputSchema),z.lazy(() => DocumentCreateManySigningTemplateInputSchema).array() ]),
  skipDuplicates: z.boolean().optional()
}).strict();

export const CompanyUpsertWithoutSigningTemplateInputSchema: z.ZodType<Prisma.CompanyUpsertWithoutSigningTemplateInput> = z.object({
  update: z.union([ z.lazy(() => CompanyUpdateWithoutSigningTemplateInputSchema),z.lazy(() => CompanyUncheckedUpdateWithoutSigningTemplateInputSchema) ]),
  create: z.union([ z.lazy(() => CompanyCreateWithoutSigningTemplateInputSchema),z.lazy(() => CompanyUncheckedCreateWithoutSigningTemplateInputSchema) ]),
  where: z.lazy(() => CompanyWhereInputSchema).optional()
}).strict();

export const CompanyUpdateToOneWithWhereWithoutSigningTemplateInputSchema: z.ZodType<Prisma.CompanyUpdateToOneWithWhereWithoutSigningTemplateInput> = z.object({
  where: z.lazy(() => CompanyWhereInputSchema).optional(),
  data: z.union([ z.lazy(() => CompanyUpdateWithoutSigningTemplateInputSchema),z.lazy(() => CompanyUncheckedUpdateWithoutSigningTemplateInputSchema) ]),
}).strict();

export const CompanyUpdateWithoutSigningTemplateInputSchema: z.ZodType<Prisma.CompanyUpdateWithoutSigningTemplateInput> = z.object({
  id: z.union([ z.number().int(),z.lazy(() => IntFieldUpdateOperationsInputSchema) ]).optional(),
  name: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  adminEmail: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  country: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  rootCertificate: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  subscriptionId: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  createdAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  updatedAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  users: z.lazy(() => UserUpdateManyWithoutCompanyNestedInputSchema).optional(),
  documents: z.lazy(() => DocumentUpdateManyWithoutCompanyNestedInputSchema).optional(),
  certificates: z.lazy(() => CertificateUpdateManyWithoutCompanyNestedInputSchema).optional(),
  blockchainWallet: z.lazy(() => BlockchainWalletUpdateOneWithoutCompanyNestedInputSchema).optional(),
  ApiKey: z.lazy(() => ApiKeyUpdateManyWithoutCompanyNestedInputSchema).optional()
}).strict();

export const CompanyUncheckedUpdateWithoutSigningTemplateInputSchema: z.ZodType<Prisma.CompanyUncheckedUpdateWithoutSigningTemplateInput> = z.object({
  id: z.union([ z.number().int(),z.lazy(() => IntFieldUpdateOperationsInputSchema) ]).optional(),
  name: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  adminEmail: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  country: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  rootCertificate: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  subscriptionId: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  createdAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  updatedAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  users: z.lazy(() => UserUncheckedUpdateManyWithoutCompanyNestedInputSchema).optional(),
  documents: z.lazy(() => DocumentUncheckedUpdateManyWithoutCompanyNestedInputSchema).optional(),
  certificates: z.lazy(() => CertificateUncheckedUpdateManyWithoutCompanyNestedInputSchema).optional(),
  blockchainWallet: z.lazy(() => BlockchainWalletUncheckedUpdateOneWithoutCompanyNestedInputSchema).optional(),
  ApiKey: z.lazy(() => ApiKeyUncheckedUpdateManyWithoutCompanyNestedInputSchema).optional()
}).strict();

export const DocumentUpsertWithWhereUniqueWithoutSigningTemplateInputSchema: z.ZodType<Prisma.DocumentUpsertWithWhereUniqueWithoutSigningTemplateInput> = z.object({
  where: z.lazy(() => DocumentWhereUniqueInputSchema),
  update: z.union([ z.lazy(() => DocumentUpdateWithoutSigningTemplateInputSchema),z.lazy(() => DocumentUncheckedUpdateWithoutSigningTemplateInputSchema) ]),
  create: z.union([ z.lazy(() => DocumentCreateWithoutSigningTemplateInputSchema),z.lazy(() => DocumentUncheckedCreateWithoutSigningTemplateInputSchema) ]),
}).strict();

export const DocumentUpdateWithWhereUniqueWithoutSigningTemplateInputSchema: z.ZodType<Prisma.DocumentUpdateWithWhereUniqueWithoutSigningTemplateInput> = z.object({
  where: z.lazy(() => DocumentWhereUniqueInputSchema),
  data: z.union([ z.lazy(() => DocumentUpdateWithoutSigningTemplateInputSchema),z.lazy(() => DocumentUncheckedUpdateWithoutSigningTemplateInputSchema) ]),
}).strict();

export const DocumentUpdateManyWithWhereWithoutSigningTemplateInputSchema: z.ZodType<Prisma.DocumentUpdateManyWithWhereWithoutSigningTemplateInput> = z.object({
  where: z.lazy(() => DocumentScalarWhereInputSchema),
  data: z.union([ z.lazy(() => DocumentUpdateManyMutationInputSchema),z.lazy(() => DocumentUncheckedUpdateManyWithoutSigningTemplateInputSchema) ]),
}).strict();

export const CompanyCreateWithoutBlockchainWalletInputSchema: z.ZodType<Prisma.CompanyCreateWithoutBlockchainWalletInput> = z.object({
  id: z.number().int(),
  name: z.string(),
  adminEmail: z.string(),
  country: z.string(),
  rootCertificate: z.string().optional().nullable(),
  subscriptionId: z.string().optional().nullable(),
  createdAt: z.coerce.date().optional(),
  updatedAt: z.coerce.date().optional(),
  users: z.lazy(() => UserCreateNestedManyWithoutCompanyInputSchema).optional(),
  documents: z.lazy(() => DocumentCreateNestedManyWithoutCompanyInputSchema).optional(),
  certificates: z.lazy(() => CertificateCreateNestedManyWithoutCompanyInputSchema).optional(),
  SigningTemplate: z.lazy(() => SigningTemplateCreateNestedManyWithoutCompanyInputSchema).optional(),
  ApiKey: z.lazy(() => ApiKeyCreateNestedManyWithoutCompanyInputSchema).optional()
}).strict();

export const CompanyUncheckedCreateWithoutBlockchainWalletInputSchema: z.ZodType<Prisma.CompanyUncheckedCreateWithoutBlockchainWalletInput> = z.object({
  id: z.number().int(),
  name: z.string(),
  adminEmail: z.string(),
  country: z.string(),
  rootCertificate: z.string().optional().nullable(),
  subscriptionId: z.string().optional().nullable(),
  createdAt: z.coerce.date().optional(),
  updatedAt: z.coerce.date().optional(),
  users: z.lazy(() => UserUncheckedCreateNestedManyWithoutCompanyInputSchema).optional(),
  documents: z.lazy(() => DocumentUncheckedCreateNestedManyWithoutCompanyInputSchema).optional(),
  certificates: z.lazy(() => CertificateUncheckedCreateNestedManyWithoutCompanyInputSchema).optional(),
  SigningTemplate: z.lazy(() => SigningTemplateUncheckedCreateNestedManyWithoutCompanyInputSchema).optional(),
  ApiKey: z.lazy(() => ApiKeyUncheckedCreateNestedManyWithoutCompanyInputSchema).optional()
}).strict();

export const CompanyCreateOrConnectWithoutBlockchainWalletInputSchema: z.ZodType<Prisma.CompanyCreateOrConnectWithoutBlockchainWalletInput> = z.object({
  where: z.lazy(() => CompanyWhereUniqueInputSchema),
  create: z.union([ z.lazy(() => CompanyCreateWithoutBlockchainWalletInputSchema),z.lazy(() => CompanyUncheckedCreateWithoutBlockchainWalletInputSchema) ]),
}).strict();

export const CompanyUpsertWithoutBlockchainWalletInputSchema: z.ZodType<Prisma.CompanyUpsertWithoutBlockchainWalletInput> = z.object({
  update: z.union([ z.lazy(() => CompanyUpdateWithoutBlockchainWalletInputSchema),z.lazy(() => CompanyUncheckedUpdateWithoutBlockchainWalletInputSchema) ]),
  create: z.union([ z.lazy(() => CompanyCreateWithoutBlockchainWalletInputSchema),z.lazy(() => CompanyUncheckedCreateWithoutBlockchainWalletInputSchema) ]),
  where: z.lazy(() => CompanyWhereInputSchema).optional()
}).strict();

export const CompanyUpdateToOneWithWhereWithoutBlockchainWalletInputSchema: z.ZodType<Prisma.CompanyUpdateToOneWithWhereWithoutBlockchainWalletInput> = z.object({
  where: z.lazy(() => CompanyWhereInputSchema).optional(),
  data: z.union([ z.lazy(() => CompanyUpdateWithoutBlockchainWalletInputSchema),z.lazy(() => CompanyUncheckedUpdateWithoutBlockchainWalletInputSchema) ]),
}).strict();

export const CompanyUpdateWithoutBlockchainWalletInputSchema: z.ZodType<Prisma.CompanyUpdateWithoutBlockchainWalletInput> = z.object({
  id: z.union([ z.number().int(),z.lazy(() => IntFieldUpdateOperationsInputSchema) ]).optional(),
  name: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  adminEmail: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  country: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  rootCertificate: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  subscriptionId: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  createdAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  updatedAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  users: z.lazy(() => UserUpdateManyWithoutCompanyNestedInputSchema).optional(),
  documents: z.lazy(() => DocumentUpdateManyWithoutCompanyNestedInputSchema).optional(),
  certificates: z.lazy(() => CertificateUpdateManyWithoutCompanyNestedInputSchema).optional(),
  SigningTemplate: z.lazy(() => SigningTemplateUpdateManyWithoutCompanyNestedInputSchema).optional(),
  ApiKey: z.lazy(() => ApiKeyUpdateManyWithoutCompanyNestedInputSchema).optional()
}).strict();

export const CompanyUncheckedUpdateWithoutBlockchainWalletInputSchema: z.ZodType<Prisma.CompanyUncheckedUpdateWithoutBlockchainWalletInput> = z.object({
  id: z.union([ z.number().int(),z.lazy(() => IntFieldUpdateOperationsInputSchema) ]).optional(),
  name: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  adminEmail: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  country: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  rootCertificate: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  subscriptionId: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  createdAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  updatedAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  users: z.lazy(() => UserUncheckedUpdateManyWithoutCompanyNestedInputSchema).optional(),
  documents: z.lazy(() => DocumentUncheckedUpdateManyWithoutCompanyNestedInputSchema).optional(),
  certificates: z.lazy(() => CertificateUncheckedUpdateManyWithoutCompanyNestedInputSchema).optional(),
  SigningTemplate: z.lazy(() => SigningTemplateUncheckedUpdateManyWithoutCompanyNestedInputSchema).optional(),
  ApiKey: z.lazy(() => ApiKeyUncheckedUpdateManyWithoutCompanyNestedInputSchema).optional()
}).strict();

export const CompanyCreateWithoutApiKeyInputSchema: z.ZodType<Prisma.CompanyCreateWithoutApiKeyInput> = z.object({
  id: z.number().int(),
  name: z.string(),
  adminEmail: z.string(),
  country: z.string(),
  rootCertificate: z.string().optional().nullable(),
  subscriptionId: z.string().optional().nullable(),
  createdAt: z.coerce.date().optional(),
  updatedAt: z.coerce.date().optional(),
  users: z.lazy(() => UserCreateNestedManyWithoutCompanyInputSchema).optional(),
  documents: z.lazy(() => DocumentCreateNestedManyWithoutCompanyInputSchema).optional(),
  certificates: z.lazy(() => CertificateCreateNestedManyWithoutCompanyInputSchema).optional(),
  blockchainWallet: z.lazy(() => BlockchainWalletCreateNestedOneWithoutCompanyInputSchema).optional(),
  SigningTemplate: z.lazy(() => SigningTemplateCreateNestedManyWithoutCompanyInputSchema).optional()
}).strict();

export const CompanyUncheckedCreateWithoutApiKeyInputSchema: z.ZodType<Prisma.CompanyUncheckedCreateWithoutApiKeyInput> = z.object({
  id: z.number().int(),
  name: z.string(),
  adminEmail: z.string(),
  country: z.string(),
  rootCertificate: z.string().optional().nullable(),
  subscriptionId: z.string().optional().nullable(),
  createdAt: z.coerce.date().optional(),
  updatedAt: z.coerce.date().optional(),
  users: z.lazy(() => UserUncheckedCreateNestedManyWithoutCompanyInputSchema).optional(),
  documents: z.lazy(() => DocumentUncheckedCreateNestedManyWithoutCompanyInputSchema).optional(),
  certificates: z.lazy(() => CertificateUncheckedCreateNestedManyWithoutCompanyInputSchema).optional(),
  blockchainWallet: z.lazy(() => BlockchainWalletUncheckedCreateNestedOneWithoutCompanyInputSchema).optional(),
  SigningTemplate: z.lazy(() => SigningTemplateUncheckedCreateNestedManyWithoutCompanyInputSchema).optional()
}).strict();

export const CompanyCreateOrConnectWithoutApiKeyInputSchema: z.ZodType<Prisma.CompanyCreateOrConnectWithoutApiKeyInput> = z.object({
  where: z.lazy(() => CompanyWhereUniqueInputSchema),
  create: z.union([ z.lazy(() => CompanyCreateWithoutApiKeyInputSchema),z.lazy(() => CompanyUncheckedCreateWithoutApiKeyInputSchema) ]),
}).strict();

export const UserCreateWithoutApiKeysInputSchema: z.ZodType<Prisma.UserCreateWithoutApiKeysInput> = z.object({
  id: z.string().uuid().optional(),
  email: z.string(),
  name: z.string(),
  role: z.lazy(() => UserRoleSchema).optional(),
  createdAt: z.coerce.date().optional(),
  updatedAt: z.coerce.date().optional(),
  company: z.lazy(() => CompanyCreateNestedOneWithoutUsersInputSchema),
  documents: z.lazy(() => DocumentCreateNestedManyWithoutUserInputSchema).optional(),
  signatures: z.lazy(() => SignatureCreateNestedManyWithoutUserInputSchema).optional()
}).strict();

export const UserUncheckedCreateWithoutApiKeysInputSchema: z.ZodType<Prisma.UserUncheckedCreateWithoutApiKeysInput> = z.object({
  id: z.string().uuid().optional(),
  email: z.string(),
  name: z.string(),
  companyId: z.number().int(),
  role: z.lazy(() => UserRoleSchema).optional(),
  createdAt: z.coerce.date().optional(),
  updatedAt: z.coerce.date().optional(),
  documents: z.lazy(() => DocumentUncheckedCreateNestedManyWithoutUserInputSchema).optional(),
  signatures: z.lazy(() => SignatureUncheckedCreateNestedManyWithoutUserInputSchema).optional()
}).strict();

export const UserCreateOrConnectWithoutApiKeysInputSchema: z.ZodType<Prisma.UserCreateOrConnectWithoutApiKeysInput> = z.object({
  where: z.lazy(() => UserWhereUniqueInputSchema),
  create: z.union([ z.lazy(() => UserCreateWithoutApiKeysInputSchema),z.lazy(() => UserUncheckedCreateWithoutApiKeysInputSchema) ]),
}).strict();

export const CompanyUpsertWithoutApiKeyInputSchema: z.ZodType<Prisma.CompanyUpsertWithoutApiKeyInput> = z.object({
  update: z.union([ z.lazy(() => CompanyUpdateWithoutApiKeyInputSchema),z.lazy(() => CompanyUncheckedUpdateWithoutApiKeyInputSchema) ]),
  create: z.union([ z.lazy(() => CompanyCreateWithoutApiKeyInputSchema),z.lazy(() => CompanyUncheckedCreateWithoutApiKeyInputSchema) ]),
  where: z.lazy(() => CompanyWhereInputSchema).optional()
}).strict();

export const CompanyUpdateToOneWithWhereWithoutApiKeyInputSchema: z.ZodType<Prisma.CompanyUpdateToOneWithWhereWithoutApiKeyInput> = z.object({
  where: z.lazy(() => CompanyWhereInputSchema).optional(),
  data: z.union([ z.lazy(() => CompanyUpdateWithoutApiKeyInputSchema),z.lazy(() => CompanyUncheckedUpdateWithoutApiKeyInputSchema) ]),
}).strict();

export const CompanyUpdateWithoutApiKeyInputSchema: z.ZodType<Prisma.CompanyUpdateWithoutApiKeyInput> = z.object({
  id: z.union([ z.number().int(),z.lazy(() => IntFieldUpdateOperationsInputSchema) ]).optional(),
  name: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  adminEmail: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  country: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  rootCertificate: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  subscriptionId: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  createdAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  updatedAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  users: z.lazy(() => UserUpdateManyWithoutCompanyNestedInputSchema).optional(),
  documents: z.lazy(() => DocumentUpdateManyWithoutCompanyNestedInputSchema).optional(),
  certificates: z.lazy(() => CertificateUpdateManyWithoutCompanyNestedInputSchema).optional(),
  blockchainWallet: z.lazy(() => BlockchainWalletUpdateOneWithoutCompanyNestedInputSchema).optional(),
  SigningTemplate: z.lazy(() => SigningTemplateUpdateManyWithoutCompanyNestedInputSchema).optional()
}).strict();

export const CompanyUncheckedUpdateWithoutApiKeyInputSchema: z.ZodType<Prisma.CompanyUncheckedUpdateWithoutApiKeyInput> = z.object({
  id: z.union([ z.number().int(),z.lazy(() => IntFieldUpdateOperationsInputSchema) ]).optional(),
  name: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  adminEmail: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  country: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  rootCertificate: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  subscriptionId: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  createdAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  updatedAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  users: z.lazy(() => UserUncheckedUpdateManyWithoutCompanyNestedInputSchema).optional(),
  documents: z.lazy(() => DocumentUncheckedUpdateManyWithoutCompanyNestedInputSchema).optional(),
  certificates: z.lazy(() => CertificateUncheckedUpdateManyWithoutCompanyNestedInputSchema).optional(),
  blockchainWallet: z.lazy(() => BlockchainWalletUncheckedUpdateOneWithoutCompanyNestedInputSchema).optional(),
  SigningTemplate: z.lazy(() => SigningTemplateUncheckedUpdateManyWithoutCompanyNestedInputSchema).optional()
}).strict();

export const UserUpsertWithWhereUniqueWithoutApiKeysInputSchema: z.ZodType<Prisma.UserUpsertWithWhereUniqueWithoutApiKeysInput> = z.object({
  where: z.lazy(() => UserWhereUniqueInputSchema),
  update: z.union([ z.lazy(() => UserUpdateWithoutApiKeysInputSchema),z.lazy(() => UserUncheckedUpdateWithoutApiKeysInputSchema) ]),
  create: z.union([ z.lazy(() => UserCreateWithoutApiKeysInputSchema),z.lazy(() => UserUncheckedCreateWithoutApiKeysInputSchema) ]),
}).strict();

export const UserUpdateWithWhereUniqueWithoutApiKeysInputSchema: z.ZodType<Prisma.UserUpdateWithWhereUniqueWithoutApiKeysInput> = z.object({
  where: z.lazy(() => UserWhereUniqueInputSchema),
  data: z.union([ z.lazy(() => UserUpdateWithoutApiKeysInputSchema),z.lazy(() => UserUncheckedUpdateWithoutApiKeysInputSchema) ]),
}).strict();

export const UserUpdateManyWithWhereWithoutApiKeysInputSchema: z.ZodType<Prisma.UserUpdateManyWithWhereWithoutApiKeysInput> = z.object({
  where: z.lazy(() => UserScalarWhereInputSchema),
  data: z.union([ z.lazy(() => UserUpdateManyMutationInputSchema),z.lazy(() => UserUncheckedUpdateManyWithoutApiKeysInputSchema) ]),
}).strict();

export const DocumentCreateWithoutAuditLogsInputSchema: z.ZodType<Prisma.DocumentCreateWithoutAuditLogsInput> = z.object({
  id: z.string().uuid().optional(),
  title: z.string().optional().nullable(),
  description: z.string().optional().nullable(),
  status: z.lazy(() => DocumentStatusSchema).optional(),
  fileUrl: z.string(),
  fileHash: z.string().optional().nullable(),
  blockchainDocId: z.string().optional().nullable(),
  metadata: z.union([ z.lazy(() => NullableJsonNullValueInputSchema),InputJsonValueSchema ]).optional(),
  expiresAt: z.coerce.date().optional().nullable(),
  createdAt: z.coerce.date().optional(),
  updatedAt: z.coerce.date().optional(),
  user: z.lazy(() => UserCreateNestedOneWithoutDocumentsInputSchema),
  company: z.lazy(() => CompanyCreateNestedOneWithoutDocumentsInputSchema),
  signingTemplate: z.lazy(() => SigningTemplateCreateNestedOneWithoutDocumentsInputSchema).optional(),
  signers: z.lazy(() => DocumentSignerCreateNestedManyWithoutDocumentInputSchema).optional(),
  signatures: z.lazy(() => SignatureCreateNestedManyWithoutDocumentInputSchema).optional(),
  SignatureField: z.lazy(() => SignatureFieldCreateNestedManyWithoutDocumentInputSchema).optional()
}).strict();

export const DocumentUncheckedCreateWithoutAuditLogsInputSchema: z.ZodType<Prisma.DocumentUncheckedCreateWithoutAuditLogsInput> = z.object({
  id: z.string().uuid().optional(),
  title: z.string().optional().nullable(),
  description: z.string().optional().nullable(),
  userId: z.string(),
  companyId: z.number().int(),
  status: z.lazy(() => DocumentStatusSchema).optional(),
  fileUrl: z.string(),
  fileHash: z.string().optional().nullable(),
  blockchainDocId: z.string().optional().nullable(),
  templateId: z.string().optional().nullable(),
  metadata: z.union([ z.lazy(() => NullableJsonNullValueInputSchema),InputJsonValueSchema ]).optional(),
  expiresAt: z.coerce.date().optional().nullable(),
  createdAt: z.coerce.date().optional(),
  updatedAt: z.coerce.date().optional(),
  signers: z.lazy(() => DocumentSignerUncheckedCreateNestedManyWithoutDocumentInputSchema).optional(),
  signatures: z.lazy(() => SignatureUncheckedCreateNestedManyWithoutDocumentInputSchema).optional(),
  SignatureField: z.lazy(() => SignatureFieldUncheckedCreateNestedManyWithoutDocumentInputSchema).optional()
}).strict();

export const DocumentCreateOrConnectWithoutAuditLogsInputSchema: z.ZodType<Prisma.DocumentCreateOrConnectWithoutAuditLogsInput> = z.object({
  where: z.lazy(() => DocumentWhereUniqueInputSchema),
  create: z.union([ z.lazy(() => DocumentCreateWithoutAuditLogsInputSchema),z.lazy(() => DocumentUncheckedCreateWithoutAuditLogsInputSchema) ]),
}).strict();

export const DocumentUpsertWithoutAuditLogsInputSchema: z.ZodType<Prisma.DocumentUpsertWithoutAuditLogsInput> = z.object({
  update: z.union([ z.lazy(() => DocumentUpdateWithoutAuditLogsInputSchema),z.lazy(() => DocumentUncheckedUpdateWithoutAuditLogsInputSchema) ]),
  create: z.union([ z.lazy(() => DocumentCreateWithoutAuditLogsInputSchema),z.lazy(() => DocumentUncheckedCreateWithoutAuditLogsInputSchema) ]),
  where: z.lazy(() => DocumentWhereInputSchema).optional()
}).strict();

export const DocumentUpdateToOneWithWhereWithoutAuditLogsInputSchema: z.ZodType<Prisma.DocumentUpdateToOneWithWhereWithoutAuditLogsInput> = z.object({
  where: z.lazy(() => DocumentWhereInputSchema).optional(),
  data: z.union([ z.lazy(() => DocumentUpdateWithoutAuditLogsInputSchema),z.lazy(() => DocumentUncheckedUpdateWithoutAuditLogsInputSchema) ]),
}).strict();

export const DocumentUpdateWithoutAuditLogsInputSchema: z.ZodType<Prisma.DocumentUpdateWithoutAuditLogsInput> = z.object({
  id: z.union([ z.string().uuid(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  title: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  description: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  status: z.union([ z.lazy(() => DocumentStatusSchema),z.lazy(() => EnumDocumentStatusFieldUpdateOperationsInputSchema) ]).optional(),
  fileUrl: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  fileHash: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  blockchainDocId: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  metadata: z.union([ z.lazy(() => NullableJsonNullValueInputSchema),InputJsonValueSchema ]).optional(),
  expiresAt: z.union([ z.coerce.date(),z.lazy(() => NullableDateTimeFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  createdAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  updatedAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  user: z.lazy(() => UserUpdateOneRequiredWithoutDocumentsNestedInputSchema).optional(),
  company: z.lazy(() => CompanyUpdateOneRequiredWithoutDocumentsNestedInputSchema).optional(),
  signingTemplate: z.lazy(() => SigningTemplateUpdateOneWithoutDocumentsNestedInputSchema).optional(),
  signers: z.lazy(() => DocumentSignerUpdateManyWithoutDocumentNestedInputSchema).optional(),
  signatures: z.lazy(() => SignatureUpdateManyWithoutDocumentNestedInputSchema).optional(),
  SignatureField: z.lazy(() => SignatureFieldUpdateManyWithoutDocumentNestedInputSchema).optional()
}).strict();

export const DocumentUncheckedUpdateWithoutAuditLogsInputSchema: z.ZodType<Prisma.DocumentUncheckedUpdateWithoutAuditLogsInput> = z.object({
  id: z.union([ z.string().uuid(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  title: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  description: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  userId: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  companyId: z.union([ z.number().int(),z.lazy(() => IntFieldUpdateOperationsInputSchema) ]).optional(),
  status: z.union([ z.lazy(() => DocumentStatusSchema),z.lazy(() => EnumDocumentStatusFieldUpdateOperationsInputSchema) ]).optional(),
  fileUrl: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  fileHash: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  blockchainDocId: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  templateId: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  metadata: z.union([ z.lazy(() => NullableJsonNullValueInputSchema),InputJsonValueSchema ]).optional(),
  expiresAt: z.union([ z.coerce.date(),z.lazy(() => NullableDateTimeFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  createdAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  updatedAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  signers: z.lazy(() => DocumentSignerUncheckedUpdateManyWithoutDocumentNestedInputSchema).optional(),
  signatures: z.lazy(() => SignatureUncheckedUpdateManyWithoutDocumentNestedInputSchema).optional(),
  SignatureField: z.lazy(() => SignatureFieldUncheckedUpdateManyWithoutDocumentNestedInputSchema).optional()
}).strict();

export const DocumentCreateManyUserInputSchema: z.ZodType<Prisma.DocumentCreateManyUserInput> = z.object({
  id: z.string().uuid().optional(),
  title: z.string().optional().nullable(),
  description: z.string().optional().nullable(),
  companyId: z.number().int(),
  status: z.lazy(() => DocumentStatusSchema).optional(),
  fileUrl: z.string(),
  fileHash: z.string().optional().nullable(),
  blockchainDocId: z.string().optional().nullable(),
  templateId: z.string().optional().nullable(),
  metadata: z.union([ z.lazy(() => NullableJsonNullValueInputSchema),InputJsonValueSchema ]).optional(),
  expiresAt: z.coerce.date().optional().nullable(),
  createdAt: z.coerce.date().optional(),
  updatedAt: z.coerce.date().optional()
}).strict();

export const SignatureCreateManyUserInputSchema: z.ZodType<Prisma.SignatureCreateManyUserInput> = z.object({
  id: z.string().uuid().optional(),
  documentId: z.string(),
  certificateId: z.string(),
  signatureData: z.string(),
  visualSignature: z.string().optional().nullable(),
  blockchainTx: z.string().optional().nullable(),
  coordinates: z.union([ z.lazy(() => NullableJsonNullValueInputSchema),InputJsonValueSchema ]).optional(),
  metadata: z.union([ z.lazy(() => NullableJsonNullValueInputSchema),InputJsonValueSchema ]).optional(),
  createdAt: z.coerce.date().optional(),
  updatedAt: z.coerce.date().optional()
}).strict();

export const DocumentUpdateWithoutUserInputSchema: z.ZodType<Prisma.DocumentUpdateWithoutUserInput> = z.object({
  id: z.union([ z.string().uuid(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  title: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  description: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  status: z.union([ z.lazy(() => DocumentStatusSchema),z.lazy(() => EnumDocumentStatusFieldUpdateOperationsInputSchema) ]).optional(),
  fileUrl: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  fileHash: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  blockchainDocId: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  metadata: z.union([ z.lazy(() => NullableJsonNullValueInputSchema),InputJsonValueSchema ]).optional(),
  expiresAt: z.union([ z.coerce.date(),z.lazy(() => NullableDateTimeFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  createdAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  updatedAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  company: z.lazy(() => CompanyUpdateOneRequiredWithoutDocumentsNestedInputSchema).optional(),
  signingTemplate: z.lazy(() => SigningTemplateUpdateOneWithoutDocumentsNestedInputSchema).optional(),
  signers: z.lazy(() => DocumentSignerUpdateManyWithoutDocumentNestedInputSchema).optional(),
  signatures: z.lazy(() => SignatureUpdateManyWithoutDocumentNestedInputSchema).optional(),
  auditLogs: z.lazy(() => AuditLogUpdateManyWithoutDocumentNestedInputSchema).optional(),
  SignatureField: z.lazy(() => SignatureFieldUpdateManyWithoutDocumentNestedInputSchema).optional()
}).strict();

export const DocumentUncheckedUpdateWithoutUserInputSchema: z.ZodType<Prisma.DocumentUncheckedUpdateWithoutUserInput> = z.object({
  id: z.union([ z.string().uuid(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  title: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  description: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  companyId: z.union([ z.number().int(),z.lazy(() => IntFieldUpdateOperationsInputSchema) ]).optional(),
  status: z.union([ z.lazy(() => DocumentStatusSchema),z.lazy(() => EnumDocumentStatusFieldUpdateOperationsInputSchema) ]).optional(),
  fileUrl: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  fileHash: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  blockchainDocId: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  templateId: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  metadata: z.union([ z.lazy(() => NullableJsonNullValueInputSchema),InputJsonValueSchema ]).optional(),
  expiresAt: z.union([ z.coerce.date(),z.lazy(() => NullableDateTimeFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  createdAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  updatedAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  signers: z.lazy(() => DocumentSignerUncheckedUpdateManyWithoutDocumentNestedInputSchema).optional(),
  signatures: z.lazy(() => SignatureUncheckedUpdateManyWithoutDocumentNestedInputSchema).optional(),
  auditLogs: z.lazy(() => AuditLogUncheckedUpdateManyWithoutDocumentNestedInputSchema).optional(),
  SignatureField: z.lazy(() => SignatureFieldUncheckedUpdateManyWithoutDocumentNestedInputSchema).optional()
}).strict();

export const DocumentUncheckedUpdateManyWithoutUserInputSchema: z.ZodType<Prisma.DocumentUncheckedUpdateManyWithoutUserInput> = z.object({
  id: z.union([ z.string().uuid(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  title: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  description: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  companyId: z.union([ z.number().int(),z.lazy(() => IntFieldUpdateOperationsInputSchema) ]).optional(),
  status: z.union([ z.lazy(() => DocumentStatusSchema),z.lazy(() => EnumDocumentStatusFieldUpdateOperationsInputSchema) ]).optional(),
  fileUrl: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  fileHash: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  blockchainDocId: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  templateId: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  metadata: z.union([ z.lazy(() => NullableJsonNullValueInputSchema),InputJsonValueSchema ]).optional(),
  expiresAt: z.union([ z.coerce.date(),z.lazy(() => NullableDateTimeFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  createdAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  updatedAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
}).strict();

export const SignatureUpdateWithoutUserInputSchema: z.ZodType<Prisma.SignatureUpdateWithoutUserInput> = z.object({
  id: z.union([ z.string().uuid(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  signatureData: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  visualSignature: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  blockchainTx: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  coordinates: z.union([ z.lazy(() => NullableJsonNullValueInputSchema),InputJsonValueSchema ]).optional(),
  metadata: z.union([ z.lazy(() => NullableJsonNullValueInputSchema),InputJsonValueSchema ]).optional(),
  createdAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  updatedAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  document: z.lazy(() => DocumentUpdateOneRequiredWithoutSignaturesNestedInputSchema).optional(),
  certificate: z.lazy(() => CertificateUpdateOneRequiredWithoutSignaturesNestedInputSchema).optional(),
  DocumentSigner: z.lazy(() => DocumentSignerUpdateManyWithoutSignatureNestedInputSchema).optional()
}).strict();

export const SignatureUncheckedUpdateWithoutUserInputSchema: z.ZodType<Prisma.SignatureUncheckedUpdateWithoutUserInput> = z.object({
  id: z.union([ z.string().uuid(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  documentId: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  certificateId: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  signatureData: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  visualSignature: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  blockchainTx: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  coordinates: z.union([ z.lazy(() => NullableJsonNullValueInputSchema),InputJsonValueSchema ]).optional(),
  metadata: z.union([ z.lazy(() => NullableJsonNullValueInputSchema),InputJsonValueSchema ]).optional(),
  createdAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  updatedAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  DocumentSigner: z.lazy(() => DocumentSignerUncheckedUpdateManyWithoutSignatureNestedInputSchema).optional()
}).strict();

export const SignatureUncheckedUpdateManyWithoutUserInputSchema: z.ZodType<Prisma.SignatureUncheckedUpdateManyWithoutUserInput> = z.object({
  id: z.union([ z.string().uuid(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  documentId: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  certificateId: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  signatureData: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  visualSignature: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  blockchainTx: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  coordinates: z.union([ z.lazy(() => NullableJsonNullValueInputSchema),InputJsonValueSchema ]).optional(),
  metadata: z.union([ z.lazy(() => NullableJsonNullValueInputSchema),InputJsonValueSchema ]).optional(),
  createdAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  updatedAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
}).strict();

export const ApiKeyUpdateWithoutUserInputSchema: z.ZodType<Prisma.ApiKeyUpdateWithoutUserInput> = z.object({
  id: z.union([ z.string().uuid(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  key: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  createdAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  updatedAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  isActive: z.union([ z.boolean(),z.lazy(() => BoolFieldUpdateOperationsInputSchema) ]).optional(),
  isDeleted: z.union([ z.boolean(),z.lazy(() => BoolFieldUpdateOperationsInputSchema) ]).optional(),
  isRevoked: z.union([ z.boolean(),z.lazy(() => BoolFieldUpdateOperationsInputSchema) ]).optional(),
  lastUsed: z.union([ z.coerce.date(),z.lazy(() => NullableDateTimeFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  company: z.lazy(() => CompanyUpdateOneRequiredWithoutApiKeyNestedInputSchema).optional()
}).strict();

export const ApiKeyUncheckedUpdateWithoutUserInputSchema: z.ZodType<Prisma.ApiKeyUncheckedUpdateWithoutUserInput> = z.object({
  id: z.union([ z.string().uuid(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  companyId: z.union([ z.number().int(),z.lazy(() => IntFieldUpdateOperationsInputSchema) ]).optional(),
  key: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  createdAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  updatedAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  isActive: z.union([ z.boolean(),z.lazy(() => BoolFieldUpdateOperationsInputSchema) ]).optional(),
  isDeleted: z.union([ z.boolean(),z.lazy(() => BoolFieldUpdateOperationsInputSchema) ]).optional(),
  isRevoked: z.union([ z.boolean(),z.lazy(() => BoolFieldUpdateOperationsInputSchema) ]).optional(),
  lastUsed: z.union([ z.coerce.date(),z.lazy(() => NullableDateTimeFieldUpdateOperationsInputSchema) ]).optional().nullable(),
}).strict();

export const ApiKeyUncheckedUpdateManyWithoutUserInputSchema: z.ZodType<Prisma.ApiKeyUncheckedUpdateManyWithoutUserInput> = z.object({
  id: z.union([ z.string().uuid(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  companyId: z.union([ z.number().int(),z.lazy(() => IntFieldUpdateOperationsInputSchema) ]).optional(),
  key: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  createdAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  updatedAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  isActive: z.union([ z.boolean(),z.lazy(() => BoolFieldUpdateOperationsInputSchema) ]).optional(),
  isDeleted: z.union([ z.boolean(),z.lazy(() => BoolFieldUpdateOperationsInputSchema) ]).optional(),
  isRevoked: z.union([ z.boolean(),z.lazy(() => BoolFieldUpdateOperationsInputSchema) ]).optional(),
  lastUsed: z.union([ z.coerce.date(),z.lazy(() => NullableDateTimeFieldUpdateOperationsInputSchema) ]).optional().nullable(),
}).strict();

export const UserCreateManyCompanyInputSchema: z.ZodType<Prisma.UserCreateManyCompanyInput> = z.object({
  id: z.string().uuid().optional(),
  email: z.string(),
  name: z.string(),
  role: z.lazy(() => UserRoleSchema).optional(),
  createdAt: z.coerce.date().optional(),
  updatedAt: z.coerce.date().optional()
}).strict();

export const DocumentCreateManyCompanyInputSchema: z.ZodType<Prisma.DocumentCreateManyCompanyInput> = z.object({
  id: z.string().uuid().optional(),
  title: z.string().optional().nullable(),
  description: z.string().optional().nullable(),
  userId: z.string(),
  status: z.lazy(() => DocumentStatusSchema).optional(),
  fileUrl: z.string(),
  fileHash: z.string().optional().nullable(),
  blockchainDocId: z.string().optional().nullable(),
  templateId: z.string().optional().nullable(),
  metadata: z.union([ z.lazy(() => NullableJsonNullValueInputSchema),InputJsonValueSchema ]).optional(),
  expiresAt: z.coerce.date().optional().nullable(),
  createdAt: z.coerce.date().optional(),
  updatedAt: z.coerce.date().optional()
}).strict();

export const CertificateCreateManyCompanyInputSchema: z.ZodType<Prisma.CertificateCreateManyCompanyInput> = z.object({
  id: z.string().uuid().optional(),
  fingerprint: z.string(),
  publicKey: z.string(),
  privateKey: z.string().optional().nullable(),
  isCA: z.boolean().optional(),
  issuerCertId: z.string().optional().nullable(),
  validFrom: z.coerce.date(),
  validTo: z.coerce.date(),
  metadata: z.union([ z.lazy(() => NullableJsonNullValueInputSchema),InputJsonValueSchema ]).optional(),
  createdAt: z.coerce.date().optional(),
  updatedAt: z.coerce.date().optional()
}).strict();

export const SigningTemplateCreateManyCompanyInputSchema: z.ZodType<Prisma.SigningTemplateCreateManyCompanyInput> = z.object({
  id: z.string().uuid().optional(),
  name: z.string(),
  fields: z.union([ z.lazy(() => JsonNullValueInputSchema),InputJsonValueSchema ]),
  createdAt: z.coerce.date().optional(),
  updatedAt: z.coerce.date().optional()
}).strict();

export const ApiKeyCreateManyCompanyInputSchema: z.ZodType<Prisma.ApiKeyCreateManyCompanyInput> = z.object({
  id: z.string().uuid().optional(),
  key: z.string(),
  createdAt: z.coerce.date().optional(),
  updatedAt: z.coerce.date().optional(),
  isActive: z.boolean().optional(),
  isDeleted: z.boolean().optional(),
  isRevoked: z.boolean().optional(),
  lastUsed: z.coerce.date().optional().nullable()
}).strict();

export const UserUpdateWithoutCompanyInputSchema: z.ZodType<Prisma.UserUpdateWithoutCompanyInput> = z.object({
  id: z.union([ z.string().uuid(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  email: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  name: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  role: z.union([ z.lazy(() => UserRoleSchema),z.lazy(() => EnumUserRoleFieldUpdateOperationsInputSchema) ]).optional(),
  createdAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  updatedAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  documents: z.lazy(() => DocumentUpdateManyWithoutUserNestedInputSchema).optional(),
  signatures: z.lazy(() => SignatureUpdateManyWithoutUserNestedInputSchema).optional(),
  apiKeys: z.lazy(() => ApiKeyUpdateManyWithoutUserNestedInputSchema).optional()
}).strict();

export const UserUncheckedUpdateWithoutCompanyInputSchema: z.ZodType<Prisma.UserUncheckedUpdateWithoutCompanyInput> = z.object({
  id: z.union([ z.string().uuid(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  email: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  name: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  role: z.union([ z.lazy(() => UserRoleSchema),z.lazy(() => EnumUserRoleFieldUpdateOperationsInputSchema) ]).optional(),
  createdAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  updatedAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  documents: z.lazy(() => DocumentUncheckedUpdateManyWithoutUserNestedInputSchema).optional(),
  signatures: z.lazy(() => SignatureUncheckedUpdateManyWithoutUserNestedInputSchema).optional(),
  apiKeys: z.lazy(() => ApiKeyUncheckedUpdateManyWithoutUserNestedInputSchema).optional()
}).strict();

export const UserUncheckedUpdateManyWithoutCompanyInputSchema: z.ZodType<Prisma.UserUncheckedUpdateManyWithoutCompanyInput> = z.object({
  id: z.union([ z.string().uuid(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  email: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  name: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  role: z.union([ z.lazy(() => UserRoleSchema),z.lazy(() => EnumUserRoleFieldUpdateOperationsInputSchema) ]).optional(),
  createdAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  updatedAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
}).strict();

export const DocumentUpdateWithoutCompanyInputSchema: z.ZodType<Prisma.DocumentUpdateWithoutCompanyInput> = z.object({
  id: z.union([ z.string().uuid(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  title: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  description: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  status: z.union([ z.lazy(() => DocumentStatusSchema),z.lazy(() => EnumDocumentStatusFieldUpdateOperationsInputSchema) ]).optional(),
  fileUrl: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  fileHash: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  blockchainDocId: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  metadata: z.union([ z.lazy(() => NullableJsonNullValueInputSchema),InputJsonValueSchema ]).optional(),
  expiresAt: z.union([ z.coerce.date(),z.lazy(() => NullableDateTimeFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  createdAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  updatedAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  user: z.lazy(() => UserUpdateOneRequiredWithoutDocumentsNestedInputSchema).optional(),
  signingTemplate: z.lazy(() => SigningTemplateUpdateOneWithoutDocumentsNestedInputSchema).optional(),
  signers: z.lazy(() => DocumentSignerUpdateManyWithoutDocumentNestedInputSchema).optional(),
  signatures: z.lazy(() => SignatureUpdateManyWithoutDocumentNestedInputSchema).optional(),
  auditLogs: z.lazy(() => AuditLogUpdateManyWithoutDocumentNestedInputSchema).optional(),
  SignatureField: z.lazy(() => SignatureFieldUpdateManyWithoutDocumentNestedInputSchema).optional()
}).strict();

export const DocumentUncheckedUpdateWithoutCompanyInputSchema: z.ZodType<Prisma.DocumentUncheckedUpdateWithoutCompanyInput> = z.object({
  id: z.union([ z.string().uuid(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  title: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  description: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  userId: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  status: z.union([ z.lazy(() => DocumentStatusSchema),z.lazy(() => EnumDocumentStatusFieldUpdateOperationsInputSchema) ]).optional(),
  fileUrl: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  fileHash: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  blockchainDocId: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  templateId: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  metadata: z.union([ z.lazy(() => NullableJsonNullValueInputSchema),InputJsonValueSchema ]).optional(),
  expiresAt: z.union([ z.coerce.date(),z.lazy(() => NullableDateTimeFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  createdAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  updatedAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  signers: z.lazy(() => DocumentSignerUncheckedUpdateManyWithoutDocumentNestedInputSchema).optional(),
  signatures: z.lazy(() => SignatureUncheckedUpdateManyWithoutDocumentNestedInputSchema).optional(),
  auditLogs: z.lazy(() => AuditLogUncheckedUpdateManyWithoutDocumentNestedInputSchema).optional(),
  SignatureField: z.lazy(() => SignatureFieldUncheckedUpdateManyWithoutDocumentNestedInputSchema).optional()
}).strict();

export const DocumentUncheckedUpdateManyWithoutCompanyInputSchema: z.ZodType<Prisma.DocumentUncheckedUpdateManyWithoutCompanyInput> = z.object({
  id: z.union([ z.string().uuid(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  title: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  description: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  userId: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  status: z.union([ z.lazy(() => DocumentStatusSchema),z.lazy(() => EnumDocumentStatusFieldUpdateOperationsInputSchema) ]).optional(),
  fileUrl: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  fileHash: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  blockchainDocId: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  templateId: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  metadata: z.union([ z.lazy(() => NullableJsonNullValueInputSchema),InputJsonValueSchema ]).optional(),
  expiresAt: z.union([ z.coerce.date(),z.lazy(() => NullableDateTimeFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  createdAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  updatedAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
}).strict();

export const CertificateUpdateWithoutCompanyInputSchema: z.ZodType<Prisma.CertificateUpdateWithoutCompanyInput> = z.object({
  id: z.union([ z.string().uuid(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  fingerprint: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  publicKey: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  privateKey: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  isCA: z.union([ z.boolean(),z.lazy(() => BoolFieldUpdateOperationsInputSchema) ]).optional(),
  issuerCertId: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  validFrom: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  validTo: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  metadata: z.union([ z.lazy(() => NullableJsonNullValueInputSchema),InputJsonValueSchema ]).optional(),
  createdAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  updatedAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  signatures: z.lazy(() => SignatureUpdateManyWithoutCertificateNestedInputSchema).optional()
}).strict();

export const CertificateUncheckedUpdateWithoutCompanyInputSchema: z.ZodType<Prisma.CertificateUncheckedUpdateWithoutCompanyInput> = z.object({
  id: z.union([ z.string().uuid(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  fingerprint: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  publicKey: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  privateKey: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  isCA: z.union([ z.boolean(),z.lazy(() => BoolFieldUpdateOperationsInputSchema) ]).optional(),
  issuerCertId: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  validFrom: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  validTo: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  metadata: z.union([ z.lazy(() => NullableJsonNullValueInputSchema),InputJsonValueSchema ]).optional(),
  createdAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  updatedAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  signatures: z.lazy(() => SignatureUncheckedUpdateManyWithoutCertificateNestedInputSchema).optional()
}).strict();

export const CertificateUncheckedUpdateManyWithoutCompanyInputSchema: z.ZodType<Prisma.CertificateUncheckedUpdateManyWithoutCompanyInput> = z.object({
  id: z.union([ z.string().uuid(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  fingerprint: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  publicKey: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  privateKey: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  isCA: z.union([ z.boolean(),z.lazy(() => BoolFieldUpdateOperationsInputSchema) ]).optional(),
  issuerCertId: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  validFrom: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  validTo: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  metadata: z.union([ z.lazy(() => NullableJsonNullValueInputSchema),InputJsonValueSchema ]).optional(),
  createdAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  updatedAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
}).strict();

export const SigningTemplateUpdateWithoutCompanyInputSchema: z.ZodType<Prisma.SigningTemplateUpdateWithoutCompanyInput> = z.object({
  id: z.union([ z.string().uuid(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  name: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  fields: z.union([ z.lazy(() => JsonNullValueInputSchema),InputJsonValueSchema ]).optional(),
  createdAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  updatedAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  documents: z.lazy(() => DocumentUpdateManyWithoutSigningTemplateNestedInputSchema).optional()
}).strict();

export const SigningTemplateUncheckedUpdateWithoutCompanyInputSchema: z.ZodType<Prisma.SigningTemplateUncheckedUpdateWithoutCompanyInput> = z.object({
  id: z.union([ z.string().uuid(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  name: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  fields: z.union([ z.lazy(() => JsonNullValueInputSchema),InputJsonValueSchema ]).optional(),
  createdAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  updatedAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  documents: z.lazy(() => DocumentUncheckedUpdateManyWithoutSigningTemplateNestedInputSchema).optional()
}).strict();

export const SigningTemplateUncheckedUpdateManyWithoutCompanyInputSchema: z.ZodType<Prisma.SigningTemplateUncheckedUpdateManyWithoutCompanyInput> = z.object({
  id: z.union([ z.string().uuid(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  name: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  fields: z.union([ z.lazy(() => JsonNullValueInputSchema),InputJsonValueSchema ]).optional(),
  createdAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  updatedAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
}).strict();

export const ApiKeyUpdateWithoutCompanyInputSchema: z.ZodType<Prisma.ApiKeyUpdateWithoutCompanyInput> = z.object({
  id: z.union([ z.string().uuid(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  key: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  createdAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  updatedAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  isActive: z.union([ z.boolean(),z.lazy(() => BoolFieldUpdateOperationsInputSchema) ]).optional(),
  isDeleted: z.union([ z.boolean(),z.lazy(() => BoolFieldUpdateOperationsInputSchema) ]).optional(),
  isRevoked: z.union([ z.boolean(),z.lazy(() => BoolFieldUpdateOperationsInputSchema) ]).optional(),
  lastUsed: z.union([ z.coerce.date(),z.lazy(() => NullableDateTimeFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  user: z.lazy(() => UserUpdateManyWithoutApiKeysNestedInputSchema).optional()
}).strict();

export const ApiKeyUncheckedUpdateWithoutCompanyInputSchema: z.ZodType<Prisma.ApiKeyUncheckedUpdateWithoutCompanyInput> = z.object({
  id: z.union([ z.string().uuid(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  key: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  createdAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  updatedAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  isActive: z.union([ z.boolean(),z.lazy(() => BoolFieldUpdateOperationsInputSchema) ]).optional(),
  isDeleted: z.union([ z.boolean(),z.lazy(() => BoolFieldUpdateOperationsInputSchema) ]).optional(),
  isRevoked: z.union([ z.boolean(),z.lazy(() => BoolFieldUpdateOperationsInputSchema) ]).optional(),
  lastUsed: z.union([ z.coerce.date(),z.lazy(() => NullableDateTimeFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  user: z.lazy(() => UserUncheckedUpdateManyWithoutApiKeysNestedInputSchema).optional()
}).strict();

export const ApiKeyUncheckedUpdateManyWithoutCompanyInputSchema: z.ZodType<Prisma.ApiKeyUncheckedUpdateManyWithoutCompanyInput> = z.object({
  id: z.union([ z.string().uuid(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  key: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  createdAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  updatedAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  isActive: z.union([ z.boolean(),z.lazy(() => BoolFieldUpdateOperationsInputSchema) ]).optional(),
  isDeleted: z.union([ z.boolean(),z.lazy(() => BoolFieldUpdateOperationsInputSchema) ]).optional(),
  isRevoked: z.union([ z.boolean(),z.lazy(() => BoolFieldUpdateOperationsInputSchema) ]).optional(),
  lastUsed: z.union([ z.coerce.date(),z.lazy(() => NullableDateTimeFieldUpdateOperationsInputSchema) ]).optional().nullable(),
}).strict();

export const DocumentSignerCreateManyDocumentInputSchema: z.ZodType<Prisma.DocumentSignerCreateManyDocumentInput> = z.object({
  id: z.string().uuid().optional(),
  email: z.string(),
  name: z.string().optional().nullable(),
  order: z.number().int(),
  status: z.lazy(() => SignerStatusSchema).optional(),
  expiresAt: z.coerce.date().optional().nullable(),
  notifiedAt: z.coerce.date().optional().nullable(),
  createdAt: z.coerce.date().optional(),
  updatedAt: z.coerce.date().optional(),
  signatureId: z.string().optional().nullable()
}).strict();

export const SignatureCreateManyDocumentInputSchema: z.ZodType<Prisma.SignatureCreateManyDocumentInput> = z.object({
  id: z.string().uuid().optional(),
  userId: z.string(),
  certificateId: z.string(),
  signatureData: z.string(),
  visualSignature: z.string().optional().nullable(),
  blockchainTx: z.string().optional().nullable(),
  coordinates: z.union([ z.lazy(() => NullableJsonNullValueInputSchema),InputJsonValueSchema ]).optional(),
  metadata: z.union([ z.lazy(() => NullableJsonNullValueInputSchema),InputJsonValueSchema ]).optional(),
  createdAt: z.coerce.date().optional(),
  updatedAt: z.coerce.date().optional()
}).strict();

export const AuditLogCreateManyDocumentInputSchema: z.ZodType<Prisma.AuditLogCreateManyDocumentInput> = z.object({
  id: z.string().uuid().optional(),
  action: z.string(),
  userId: z.string().optional().nullable(),
  metadata: z.union([ z.lazy(() => NullableJsonNullValueInputSchema),InputJsonValueSchema ]).optional(),
  createdAt: z.coerce.date().optional()
}).strict();

export const SignatureFieldCreateManyDocumentInputSchema: z.ZodType<Prisma.SignatureFieldCreateManyDocumentInput> = z.object({
  id: z.string().uuid().optional(),
  signerId: z.string(),
  type: z.lazy(() => FieldTypeSchema).optional(),
  required: z.boolean().optional(),
  page: z.number().int(),
  x: z.number(),
  y: z.number(),
  width: z.number(),
  height: z.number(),
  signedAt: z.coerce.date().optional().nullable(),
  createdAt: z.coerce.date().optional(),
  updatedAt: z.coerce.date().optional()
}).strict();

export const DocumentSignerUpdateWithoutDocumentInputSchema: z.ZodType<Prisma.DocumentSignerUpdateWithoutDocumentInput> = z.object({
  id: z.union([ z.string().uuid(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  email: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  name: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  order: z.union([ z.number().int(),z.lazy(() => IntFieldUpdateOperationsInputSchema) ]).optional(),
  status: z.union([ z.lazy(() => SignerStatusSchema),z.lazy(() => EnumSignerStatusFieldUpdateOperationsInputSchema) ]).optional(),
  expiresAt: z.union([ z.coerce.date(),z.lazy(() => NullableDateTimeFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  notifiedAt: z.union([ z.coerce.date(),z.lazy(() => NullableDateTimeFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  createdAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  updatedAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  signatureFields: z.lazy(() => SignatureFieldUpdateManyWithoutSignerNestedInputSchema).optional(),
  signature: z.lazy(() => SignatureUpdateOneWithoutDocumentSignerNestedInputSchema).optional()
}).strict();

export const DocumentSignerUncheckedUpdateWithoutDocumentInputSchema: z.ZodType<Prisma.DocumentSignerUncheckedUpdateWithoutDocumentInput> = z.object({
  id: z.union([ z.string().uuid(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  email: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  name: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  order: z.union([ z.number().int(),z.lazy(() => IntFieldUpdateOperationsInputSchema) ]).optional(),
  status: z.union([ z.lazy(() => SignerStatusSchema),z.lazy(() => EnumSignerStatusFieldUpdateOperationsInputSchema) ]).optional(),
  expiresAt: z.union([ z.coerce.date(),z.lazy(() => NullableDateTimeFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  notifiedAt: z.union([ z.coerce.date(),z.lazy(() => NullableDateTimeFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  createdAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  updatedAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  signatureId: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  signatureFields: z.lazy(() => SignatureFieldUncheckedUpdateManyWithoutSignerNestedInputSchema).optional()
}).strict();

export const DocumentSignerUncheckedUpdateManyWithoutDocumentInputSchema: z.ZodType<Prisma.DocumentSignerUncheckedUpdateManyWithoutDocumentInput> = z.object({
  id: z.union([ z.string().uuid(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  email: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  name: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  order: z.union([ z.number().int(),z.lazy(() => IntFieldUpdateOperationsInputSchema) ]).optional(),
  status: z.union([ z.lazy(() => SignerStatusSchema),z.lazy(() => EnumSignerStatusFieldUpdateOperationsInputSchema) ]).optional(),
  expiresAt: z.union([ z.coerce.date(),z.lazy(() => NullableDateTimeFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  notifiedAt: z.union([ z.coerce.date(),z.lazy(() => NullableDateTimeFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  createdAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  updatedAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  signatureId: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
}).strict();

export const SignatureUpdateWithoutDocumentInputSchema: z.ZodType<Prisma.SignatureUpdateWithoutDocumentInput> = z.object({
  id: z.union([ z.string().uuid(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  signatureData: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  visualSignature: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  blockchainTx: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  coordinates: z.union([ z.lazy(() => NullableJsonNullValueInputSchema),InputJsonValueSchema ]).optional(),
  metadata: z.union([ z.lazy(() => NullableJsonNullValueInputSchema),InputJsonValueSchema ]).optional(),
  createdAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  updatedAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  user: z.lazy(() => UserUpdateOneRequiredWithoutSignaturesNestedInputSchema).optional(),
  certificate: z.lazy(() => CertificateUpdateOneRequiredWithoutSignaturesNestedInputSchema).optional(),
  DocumentSigner: z.lazy(() => DocumentSignerUpdateManyWithoutSignatureNestedInputSchema).optional()
}).strict();

export const SignatureUncheckedUpdateWithoutDocumentInputSchema: z.ZodType<Prisma.SignatureUncheckedUpdateWithoutDocumentInput> = z.object({
  id: z.union([ z.string().uuid(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  userId: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  certificateId: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  signatureData: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  visualSignature: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  blockchainTx: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  coordinates: z.union([ z.lazy(() => NullableJsonNullValueInputSchema),InputJsonValueSchema ]).optional(),
  metadata: z.union([ z.lazy(() => NullableJsonNullValueInputSchema),InputJsonValueSchema ]).optional(),
  createdAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  updatedAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  DocumentSigner: z.lazy(() => DocumentSignerUncheckedUpdateManyWithoutSignatureNestedInputSchema).optional()
}).strict();

export const SignatureUncheckedUpdateManyWithoutDocumentInputSchema: z.ZodType<Prisma.SignatureUncheckedUpdateManyWithoutDocumentInput> = z.object({
  id: z.union([ z.string().uuid(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  userId: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  certificateId: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  signatureData: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  visualSignature: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  blockchainTx: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  coordinates: z.union([ z.lazy(() => NullableJsonNullValueInputSchema),InputJsonValueSchema ]).optional(),
  metadata: z.union([ z.lazy(() => NullableJsonNullValueInputSchema),InputJsonValueSchema ]).optional(),
  createdAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  updatedAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
}).strict();

export const AuditLogUpdateWithoutDocumentInputSchema: z.ZodType<Prisma.AuditLogUpdateWithoutDocumentInput> = z.object({
  id: z.union([ z.string().uuid(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  action: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  userId: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  metadata: z.union([ z.lazy(() => NullableJsonNullValueInputSchema),InputJsonValueSchema ]).optional(),
  createdAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
}).strict();

export const AuditLogUncheckedUpdateWithoutDocumentInputSchema: z.ZodType<Prisma.AuditLogUncheckedUpdateWithoutDocumentInput> = z.object({
  id: z.union([ z.string().uuid(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  action: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  userId: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  metadata: z.union([ z.lazy(() => NullableJsonNullValueInputSchema),InputJsonValueSchema ]).optional(),
  createdAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
}).strict();

export const AuditLogUncheckedUpdateManyWithoutDocumentInputSchema: z.ZodType<Prisma.AuditLogUncheckedUpdateManyWithoutDocumentInput> = z.object({
  id: z.union([ z.string().uuid(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  action: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  userId: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  metadata: z.union([ z.lazy(() => NullableJsonNullValueInputSchema),InputJsonValueSchema ]).optional(),
  createdAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
}).strict();

export const SignatureFieldUpdateWithoutDocumentInputSchema: z.ZodType<Prisma.SignatureFieldUpdateWithoutDocumentInput> = z.object({
  id: z.union([ z.string().uuid(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  type: z.union([ z.lazy(() => FieldTypeSchema),z.lazy(() => EnumFieldTypeFieldUpdateOperationsInputSchema) ]).optional(),
  required: z.union([ z.boolean(),z.lazy(() => BoolFieldUpdateOperationsInputSchema) ]).optional(),
  page: z.union([ z.number().int(),z.lazy(() => IntFieldUpdateOperationsInputSchema) ]).optional(),
  x: z.union([ z.number(),z.lazy(() => FloatFieldUpdateOperationsInputSchema) ]).optional(),
  y: z.union([ z.number(),z.lazy(() => FloatFieldUpdateOperationsInputSchema) ]).optional(),
  width: z.union([ z.number(),z.lazy(() => FloatFieldUpdateOperationsInputSchema) ]).optional(),
  height: z.union([ z.number(),z.lazy(() => FloatFieldUpdateOperationsInputSchema) ]).optional(),
  signedAt: z.union([ z.coerce.date(),z.lazy(() => NullableDateTimeFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  createdAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  updatedAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  signer: z.lazy(() => DocumentSignerUpdateOneRequiredWithoutSignatureFieldsNestedInputSchema).optional()
}).strict();

export const SignatureFieldUncheckedUpdateWithoutDocumentInputSchema: z.ZodType<Prisma.SignatureFieldUncheckedUpdateWithoutDocumentInput> = z.object({
  id: z.union([ z.string().uuid(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  signerId: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  type: z.union([ z.lazy(() => FieldTypeSchema),z.lazy(() => EnumFieldTypeFieldUpdateOperationsInputSchema) ]).optional(),
  required: z.union([ z.boolean(),z.lazy(() => BoolFieldUpdateOperationsInputSchema) ]).optional(),
  page: z.union([ z.number().int(),z.lazy(() => IntFieldUpdateOperationsInputSchema) ]).optional(),
  x: z.union([ z.number(),z.lazy(() => FloatFieldUpdateOperationsInputSchema) ]).optional(),
  y: z.union([ z.number(),z.lazy(() => FloatFieldUpdateOperationsInputSchema) ]).optional(),
  width: z.union([ z.number(),z.lazy(() => FloatFieldUpdateOperationsInputSchema) ]).optional(),
  height: z.union([ z.number(),z.lazy(() => FloatFieldUpdateOperationsInputSchema) ]).optional(),
  signedAt: z.union([ z.coerce.date(),z.lazy(() => NullableDateTimeFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  createdAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  updatedAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
}).strict();

export const SignatureFieldUncheckedUpdateManyWithoutDocumentInputSchema: z.ZodType<Prisma.SignatureFieldUncheckedUpdateManyWithoutDocumentInput> = z.object({
  id: z.union([ z.string().uuid(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  signerId: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  type: z.union([ z.lazy(() => FieldTypeSchema),z.lazy(() => EnumFieldTypeFieldUpdateOperationsInputSchema) ]).optional(),
  required: z.union([ z.boolean(),z.lazy(() => BoolFieldUpdateOperationsInputSchema) ]).optional(),
  page: z.union([ z.number().int(),z.lazy(() => IntFieldUpdateOperationsInputSchema) ]).optional(),
  x: z.union([ z.number(),z.lazy(() => FloatFieldUpdateOperationsInputSchema) ]).optional(),
  y: z.union([ z.number(),z.lazy(() => FloatFieldUpdateOperationsInputSchema) ]).optional(),
  width: z.union([ z.number(),z.lazy(() => FloatFieldUpdateOperationsInputSchema) ]).optional(),
  height: z.union([ z.number(),z.lazy(() => FloatFieldUpdateOperationsInputSchema) ]).optional(),
  signedAt: z.union([ z.coerce.date(),z.lazy(() => NullableDateTimeFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  createdAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  updatedAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
}).strict();

export const SignatureFieldCreateManySignerInputSchema: z.ZodType<Prisma.SignatureFieldCreateManySignerInput> = z.object({
  id: z.string().uuid().optional(),
  documentId: z.string(),
  type: z.lazy(() => FieldTypeSchema).optional(),
  required: z.boolean().optional(),
  page: z.number().int(),
  x: z.number(),
  y: z.number(),
  width: z.number(),
  height: z.number(),
  signedAt: z.coerce.date().optional().nullable(),
  createdAt: z.coerce.date().optional(),
  updatedAt: z.coerce.date().optional()
}).strict();

export const SignatureFieldUpdateWithoutSignerInputSchema: z.ZodType<Prisma.SignatureFieldUpdateWithoutSignerInput> = z.object({
  id: z.union([ z.string().uuid(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  type: z.union([ z.lazy(() => FieldTypeSchema),z.lazy(() => EnumFieldTypeFieldUpdateOperationsInputSchema) ]).optional(),
  required: z.union([ z.boolean(),z.lazy(() => BoolFieldUpdateOperationsInputSchema) ]).optional(),
  page: z.union([ z.number().int(),z.lazy(() => IntFieldUpdateOperationsInputSchema) ]).optional(),
  x: z.union([ z.number(),z.lazy(() => FloatFieldUpdateOperationsInputSchema) ]).optional(),
  y: z.union([ z.number(),z.lazy(() => FloatFieldUpdateOperationsInputSchema) ]).optional(),
  width: z.union([ z.number(),z.lazy(() => FloatFieldUpdateOperationsInputSchema) ]).optional(),
  height: z.union([ z.number(),z.lazy(() => FloatFieldUpdateOperationsInputSchema) ]).optional(),
  signedAt: z.union([ z.coerce.date(),z.lazy(() => NullableDateTimeFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  createdAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  updatedAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  document: z.lazy(() => DocumentUpdateOneRequiredWithoutSignatureFieldNestedInputSchema).optional()
}).strict();

export const SignatureFieldUncheckedUpdateWithoutSignerInputSchema: z.ZodType<Prisma.SignatureFieldUncheckedUpdateWithoutSignerInput> = z.object({
  id: z.union([ z.string().uuid(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  documentId: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  type: z.union([ z.lazy(() => FieldTypeSchema),z.lazy(() => EnumFieldTypeFieldUpdateOperationsInputSchema) ]).optional(),
  required: z.union([ z.boolean(),z.lazy(() => BoolFieldUpdateOperationsInputSchema) ]).optional(),
  page: z.union([ z.number().int(),z.lazy(() => IntFieldUpdateOperationsInputSchema) ]).optional(),
  x: z.union([ z.number(),z.lazy(() => FloatFieldUpdateOperationsInputSchema) ]).optional(),
  y: z.union([ z.number(),z.lazy(() => FloatFieldUpdateOperationsInputSchema) ]).optional(),
  width: z.union([ z.number(),z.lazy(() => FloatFieldUpdateOperationsInputSchema) ]).optional(),
  height: z.union([ z.number(),z.lazy(() => FloatFieldUpdateOperationsInputSchema) ]).optional(),
  signedAt: z.union([ z.coerce.date(),z.lazy(() => NullableDateTimeFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  createdAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  updatedAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
}).strict();

export const SignatureFieldUncheckedUpdateManyWithoutSignerInputSchema: z.ZodType<Prisma.SignatureFieldUncheckedUpdateManyWithoutSignerInput> = z.object({
  id: z.union([ z.string().uuid(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  documentId: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  type: z.union([ z.lazy(() => FieldTypeSchema),z.lazy(() => EnumFieldTypeFieldUpdateOperationsInputSchema) ]).optional(),
  required: z.union([ z.boolean(),z.lazy(() => BoolFieldUpdateOperationsInputSchema) ]).optional(),
  page: z.union([ z.number().int(),z.lazy(() => IntFieldUpdateOperationsInputSchema) ]).optional(),
  x: z.union([ z.number(),z.lazy(() => FloatFieldUpdateOperationsInputSchema) ]).optional(),
  y: z.union([ z.number(),z.lazy(() => FloatFieldUpdateOperationsInputSchema) ]).optional(),
  width: z.union([ z.number(),z.lazy(() => FloatFieldUpdateOperationsInputSchema) ]).optional(),
  height: z.union([ z.number(),z.lazy(() => FloatFieldUpdateOperationsInputSchema) ]).optional(),
  signedAt: z.union([ z.coerce.date(),z.lazy(() => NullableDateTimeFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  createdAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  updatedAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
}).strict();

export const DocumentSignerCreateManySignatureInputSchema: z.ZodType<Prisma.DocumentSignerCreateManySignatureInput> = z.object({
  id: z.string().uuid().optional(),
  documentId: z.string(),
  email: z.string(),
  name: z.string().optional().nullable(),
  order: z.number().int(),
  status: z.lazy(() => SignerStatusSchema).optional(),
  expiresAt: z.coerce.date().optional().nullable(),
  notifiedAt: z.coerce.date().optional().nullable(),
  createdAt: z.coerce.date().optional(),
  updatedAt: z.coerce.date().optional()
}).strict();

export const DocumentSignerUpdateWithoutSignatureInputSchema: z.ZodType<Prisma.DocumentSignerUpdateWithoutSignatureInput> = z.object({
  id: z.union([ z.string().uuid(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  email: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  name: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  order: z.union([ z.number().int(),z.lazy(() => IntFieldUpdateOperationsInputSchema) ]).optional(),
  status: z.union([ z.lazy(() => SignerStatusSchema),z.lazy(() => EnumSignerStatusFieldUpdateOperationsInputSchema) ]).optional(),
  expiresAt: z.union([ z.coerce.date(),z.lazy(() => NullableDateTimeFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  notifiedAt: z.union([ z.coerce.date(),z.lazy(() => NullableDateTimeFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  createdAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  updatedAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  document: z.lazy(() => DocumentUpdateOneRequiredWithoutSignersNestedInputSchema).optional(),
  signatureFields: z.lazy(() => SignatureFieldUpdateManyWithoutSignerNestedInputSchema).optional()
}).strict();

export const DocumentSignerUncheckedUpdateWithoutSignatureInputSchema: z.ZodType<Prisma.DocumentSignerUncheckedUpdateWithoutSignatureInput> = z.object({
  id: z.union([ z.string().uuid(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  documentId: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  email: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  name: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  order: z.union([ z.number().int(),z.lazy(() => IntFieldUpdateOperationsInputSchema) ]).optional(),
  status: z.union([ z.lazy(() => SignerStatusSchema),z.lazy(() => EnumSignerStatusFieldUpdateOperationsInputSchema) ]).optional(),
  expiresAt: z.union([ z.coerce.date(),z.lazy(() => NullableDateTimeFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  notifiedAt: z.union([ z.coerce.date(),z.lazy(() => NullableDateTimeFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  createdAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  updatedAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  signatureFields: z.lazy(() => SignatureFieldUncheckedUpdateManyWithoutSignerNestedInputSchema).optional()
}).strict();

export const DocumentSignerUncheckedUpdateManyWithoutSignatureInputSchema: z.ZodType<Prisma.DocumentSignerUncheckedUpdateManyWithoutSignatureInput> = z.object({
  id: z.union([ z.string().uuid(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  documentId: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  email: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  name: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  order: z.union([ z.number().int(),z.lazy(() => IntFieldUpdateOperationsInputSchema) ]).optional(),
  status: z.union([ z.lazy(() => SignerStatusSchema),z.lazy(() => EnumSignerStatusFieldUpdateOperationsInputSchema) ]).optional(),
  expiresAt: z.union([ z.coerce.date(),z.lazy(() => NullableDateTimeFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  notifiedAt: z.union([ z.coerce.date(),z.lazy(() => NullableDateTimeFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  createdAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  updatedAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
}).strict();

export const SignatureCreateManyCertificateInputSchema: z.ZodType<Prisma.SignatureCreateManyCertificateInput> = z.object({
  id: z.string().uuid().optional(),
  documentId: z.string(),
  userId: z.string(),
  signatureData: z.string(),
  visualSignature: z.string().optional().nullable(),
  blockchainTx: z.string().optional().nullable(),
  coordinates: z.union([ z.lazy(() => NullableJsonNullValueInputSchema),InputJsonValueSchema ]).optional(),
  metadata: z.union([ z.lazy(() => NullableJsonNullValueInputSchema),InputJsonValueSchema ]).optional(),
  createdAt: z.coerce.date().optional(),
  updatedAt: z.coerce.date().optional()
}).strict();

export const SignatureUpdateWithoutCertificateInputSchema: z.ZodType<Prisma.SignatureUpdateWithoutCertificateInput> = z.object({
  id: z.union([ z.string().uuid(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  signatureData: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  visualSignature: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  blockchainTx: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  coordinates: z.union([ z.lazy(() => NullableJsonNullValueInputSchema),InputJsonValueSchema ]).optional(),
  metadata: z.union([ z.lazy(() => NullableJsonNullValueInputSchema),InputJsonValueSchema ]).optional(),
  createdAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  updatedAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  document: z.lazy(() => DocumentUpdateOneRequiredWithoutSignaturesNestedInputSchema).optional(),
  user: z.lazy(() => UserUpdateOneRequiredWithoutSignaturesNestedInputSchema).optional(),
  DocumentSigner: z.lazy(() => DocumentSignerUpdateManyWithoutSignatureNestedInputSchema).optional()
}).strict();

export const SignatureUncheckedUpdateWithoutCertificateInputSchema: z.ZodType<Prisma.SignatureUncheckedUpdateWithoutCertificateInput> = z.object({
  id: z.union([ z.string().uuid(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  documentId: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  userId: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  signatureData: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  visualSignature: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  blockchainTx: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  coordinates: z.union([ z.lazy(() => NullableJsonNullValueInputSchema),InputJsonValueSchema ]).optional(),
  metadata: z.union([ z.lazy(() => NullableJsonNullValueInputSchema),InputJsonValueSchema ]).optional(),
  createdAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  updatedAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  DocumentSigner: z.lazy(() => DocumentSignerUncheckedUpdateManyWithoutSignatureNestedInputSchema).optional()
}).strict();

export const SignatureUncheckedUpdateManyWithoutCertificateInputSchema: z.ZodType<Prisma.SignatureUncheckedUpdateManyWithoutCertificateInput> = z.object({
  id: z.union([ z.string().uuid(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  documentId: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  userId: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  signatureData: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  visualSignature: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  blockchainTx: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  coordinates: z.union([ z.lazy(() => NullableJsonNullValueInputSchema),InputJsonValueSchema ]).optional(),
  metadata: z.union([ z.lazy(() => NullableJsonNullValueInputSchema),InputJsonValueSchema ]).optional(),
  createdAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  updatedAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
}).strict();

export const DocumentCreateManySigningTemplateInputSchema: z.ZodType<Prisma.DocumentCreateManySigningTemplateInput> = z.object({
  id: z.string().uuid().optional(),
  title: z.string().optional().nullable(),
  description: z.string().optional().nullable(),
  userId: z.string(),
  companyId: z.number().int(),
  status: z.lazy(() => DocumentStatusSchema).optional(),
  fileUrl: z.string(),
  fileHash: z.string().optional().nullable(),
  blockchainDocId: z.string().optional().nullable(),
  metadata: z.union([ z.lazy(() => NullableJsonNullValueInputSchema),InputJsonValueSchema ]).optional(),
  expiresAt: z.coerce.date().optional().nullable(),
  createdAt: z.coerce.date().optional(),
  updatedAt: z.coerce.date().optional()
}).strict();

export const DocumentUpdateWithoutSigningTemplateInputSchema: z.ZodType<Prisma.DocumentUpdateWithoutSigningTemplateInput> = z.object({
  id: z.union([ z.string().uuid(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  title: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  description: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  status: z.union([ z.lazy(() => DocumentStatusSchema),z.lazy(() => EnumDocumentStatusFieldUpdateOperationsInputSchema) ]).optional(),
  fileUrl: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  fileHash: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  blockchainDocId: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  metadata: z.union([ z.lazy(() => NullableJsonNullValueInputSchema),InputJsonValueSchema ]).optional(),
  expiresAt: z.union([ z.coerce.date(),z.lazy(() => NullableDateTimeFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  createdAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  updatedAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  user: z.lazy(() => UserUpdateOneRequiredWithoutDocumentsNestedInputSchema).optional(),
  company: z.lazy(() => CompanyUpdateOneRequiredWithoutDocumentsNestedInputSchema).optional(),
  signers: z.lazy(() => DocumentSignerUpdateManyWithoutDocumentNestedInputSchema).optional(),
  signatures: z.lazy(() => SignatureUpdateManyWithoutDocumentNestedInputSchema).optional(),
  auditLogs: z.lazy(() => AuditLogUpdateManyWithoutDocumentNestedInputSchema).optional(),
  SignatureField: z.lazy(() => SignatureFieldUpdateManyWithoutDocumentNestedInputSchema).optional()
}).strict();

export const DocumentUncheckedUpdateWithoutSigningTemplateInputSchema: z.ZodType<Prisma.DocumentUncheckedUpdateWithoutSigningTemplateInput> = z.object({
  id: z.union([ z.string().uuid(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  title: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  description: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  userId: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  companyId: z.union([ z.number().int(),z.lazy(() => IntFieldUpdateOperationsInputSchema) ]).optional(),
  status: z.union([ z.lazy(() => DocumentStatusSchema),z.lazy(() => EnumDocumentStatusFieldUpdateOperationsInputSchema) ]).optional(),
  fileUrl: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  fileHash: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  blockchainDocId: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  metadata: z.union([ z.lazy(() => NullableJsonNullValueInputSchema),InputJsonValueSchema ]).optional(),
  expiresAt: z.union([ z.coerce.date(),z.lazy(() => NullableDateTimeFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  createdAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  updatedAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  signers: z.lazy(() => DocumentSignerUncheckedUpdateManyWithoutDocumentNestedInputSchema).optional(),
  signatures: z.lazy(() => SignatureUncheckedUpdateManyWithoutDocumentNestedInputSchema).optional(),
  auditLogs: z.lazy(() => AuditLogUncheckedUpdateManyWithoutDocumentNestedInputSchema).optional(),
  SignatureField: z.lazy(() => SignatureFieldUncheckedUpdateManyWithoutDocumentNestedInputSchema).optional()
}).strict();

export const DocumentUncheckedUpdateManyWithoutSigningTemplateInputSchema: z.ZodType<Prisma.DocumentUncheckedUpdateManyWithoutSigningTemplateInput> = z.object({
  id: z.union([ z.string().uuid(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  title: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  description: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  userId: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  companyId: z.union([ z.number().int(),z.lazy(() => IntFieldUpdateOperationsInputSchema) ]).optional(),
  status: z.union([ z.lazy(() => DocumentStatusSchema),z.lazy(() => EnumDocumentStatusFieldUpdateOperationsInputSchema) ]).optional(),
  fileUrl: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  fileHash: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  blockchainDocId: z.union([ z.string(),z.lazy(() => NullableStringFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  metadata: z.union([ z.lazy(() => NullableJsonNullValueInputSchema),InputJsonValueSchema ]).optional(),
  expiresAt: z.union([ z.coerce.date(),z.lazy(() => NullableDateTimeFieldUpdateOperationsInputSchema) ]).optional().nullable(),
  createdAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  updatedAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
}).strict();

export const UserUpdateWithoutApiKeysInputSchema: z.ZodType<Prisma.UserUpdateWithoutApiKeysInput> = z.object({
  id: z.union([ z.string().uuid(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  email: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  name: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  role: z.union([ z.lazy(() => UserRoleSchema),z.lazy(() => EnumUserRoleFieldUpdateOperationsInputSchema) ]).optional(),
  createdAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  updatedAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  company: z.lazy(() => CompanyUpdateOneRequiredWithoutUsersNestedInputSchema).optional(),
  documents: z.lazy(() => DocumentUpdateManyWithoutUserNestedInputSchema).optional(),
  signatures: z.lazy(() => SignatureUpdateManyWithoutUserNestedInputSchema).optional()
}).strict();

export const UserUncheckedUpdateWithoutApiKeysInputSchema: z.ZodType<Prisma.UserUncheckedUpdateWithoutApiKeysInput> = z.object({
  id: z.union([ z.string().uuid(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  email: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  name: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  companyId: z.union([ z.number().int(),z.lazy(() => IntFieldUpdateOperationsInputSchema) ]).optional(),
  role: z.union([ z.lazy(() => UserRoleSchema),z.lazy(() => EnumUserRoleFieldUpdateOperationsInputSchema) ]).optional(),
  createdAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  updatedAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  documents: z.lazy(() => DocumentUncheckedUpdateManyWithoutUserNestedInputSchema).optional(),
  signatures: z.lazy(() => SignatureUncheckedUpdateManyWithoutUserNestedInputSchema).optional()
}).strict();

export const UserUncheckedUpdateManyWithoutApiKeysInputSchema: z.ZodType<Prisma.UserUncheckedUpdateManyWithoutApiKeysInput> = z.object({
  id: z.union([ z.string().uuid(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  email: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  name: z.union([ z.string(),z.lazy(() => StringFieldUpdateOperationsInputSchema) ]).optional(),
  companyId: z.union([ z.number().int(),z.lazy(() => IntFieldUpdateOperationsInputSchema) ]).optional(),
  role: z.union([ z.lazy(() => UserRoleSchema),z.lazy(() => EnumUserRoleFieldUpdateOperationsInputSchema) ]).optional(),
  createdAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
  updatedAt: z.union([ z.coerce.date(),z.lazy(() => DateTimeFieldUpdateOperationsInputSchema) ]).optional(),
}).strict();

/////////////////////////////////////////
// ARGS
/////////////////////////////////////////

export const UserFindFirstArgsSchema: z.ZodType<Prisma.UserFindFirstArgs> = z.object({
  select: UserSelectSchema.optional(),
  include: UserIncludeSchema.optional(),
  where: UserWhereInputSchema.optional(),
  orderBy: z.union([ UserOrderByWithRelationInputSchema.array(),UserOrderByWithRelationInputSchema ]).optional(),
  cursor: UserWhereUniqueInputSchema.optional(),
  take: z.number().optional(),
  skip: z.number().optional(),
  distinct: z.union([ UserScalarFieldEnumSchema,UserScalarFieldEnumSchema.array() ]).optional(),
}).strict() ;

export const UserFindFirstOrThrowArgsSchema: z.ZodType<Prisma.UserFindFirstOrThrowArgs> = z.object({
  select: UserSelectSchema.optional(),
  include: UserIncludeSchema.optional(),
  where: UserWhereInputSchema.optional(),
  orderBy: z.union([ UserOrderByWithRelationInputSchema.array(),UserOrderByWithRelationInputSchema ]).optional(),
  cursor: UserWhereUniqueInputSchema.optional(),
  take: z.number().optional(),
  skip: z.number().optional(),
  distinct: z.union([ UserScalarFieldEnumSchema,UserScalarFieldEnumSchema.array() ]).optional(),
}).strict() ;

export const UserFindManyArgsSchema: z.ZodType<Prisma.UserFindManyArgs> = z.object({
  select: UserSelectSchema.optional(),
  include: UserIncludeSchema.optional(),
  where: UserWhereInputSchema.optional(),
  orderBy: z.union([ UserOrderByWithRelationInputSchema.array(),UserOrderByWithRelationInputSchema ]).optional(),
  cursor: UserWhereUniqueInputSchema.optional(),
  take: z.number().optional(),
  skip: z.number().optional(),
  distinct: z.union([ UserScalarFieldEnumSchema,UserScalarFieldEnumSchema.array() ]).optional(),
}).strict() ;

export const UserAggregateArgsSchema: z.ZodType<Prisma.UserAggregateArgs> = z.object({
  where: UserWhereInputSchema.optional(),
  orderBy: z.union([ UserOrderByWithRelationInputSchema.array(),UserOrderByWithRelationInputSchema ]).optional(),
  cursor: UserWhereUniqueInputSchema.optional(),
  take: z.number().optional(),
  skip: z.number().optional(),
}).strict() ;

export const UserGroupByArgsSchema: z.ZodType<Prisma.UserGroupByArgs> = z.object({
  where: UserWhereInputSchema.optional(),
  orderBy: z.union([ UserOrderByWithAggregationInputSchema.array(),UserOrderByWithAggregationInputSchema ]).optional(),
  by: UserScalarFieldEnumSchema.array(),
  having: UserScalarWhereWithAggregatesInputSchema.optional(),
  take: z.number().optional(),
  skip: z.number().optional(),
}).strict() ;

export const UserFindUniqueArgsSchema: z.ZodType<Prisma.UserFindUniqueArgs> = z.object({
  select: UserSelectSchema.optional(),
  include: UserIncludeSchema.optional(),
  where: UserWhereUniqueInputSchema,
}).strict() ;

export const UserFindUniqueOrThrowArgsSchema: z.ZodType<Prisma.UserFindUniqueOrThrowArgs> = z.object({
  select: UserSelectSchema.optional(),
  include: UserIncludeSchema.optional(),
  where: UserWhereUniqueInputSchema,
}).strict() ;

export const CompanyFindFirstArgsSchema: z.ZodType<Prisma.CompanyFindFirstArgs> = z.object({
  select: CompanySelectSchema.optional(),
  include: CompanyIncludeSchema.optional(),
  where: CompanyWhereInputSchema.optional(),
  orderBy: z.union([ CompanyOrderByWithRelationInputSchema.array(),CompanyOrderByWithRelationInputSchema ]).optional(),
  cursor: CompanyWhereUniqueInputSchema.optional(),
  take: z.number().optional(),
  skip: z.number().optional(),
  distinct: z.union([ CompanyScalarFieldEnumSchema,CompanyScalarFieldEnumSchema.array() ]).optional(),
}).strict() ;

export const CompanyFindFirstOrThrowArgsSchema: z.ZodType<Prisma.CompanyFindFirstOrThrowArgs> = z.object({
  select: CompanySelectSchema.optional(),
  include: CompanyIncludeSchema.optional(),
  where: CompanyWhereInputSchema.optional(),
  orderBy: z.union([ CompanyOrderByWithRelationInputSchema.array(),CompanyOrderByWithRelationInputSchema ]).optional(),
  cursor: CompanyWhereUniqueInputSchema.optional(),
  take: z.number().optional(),
  skip: z.number().optional(),
  distinct: z.union([ CompanyScalarFieldEnumSchema,CompanyScalarFieldEnumSchema.array() ]).optional(),
}).strict() ;

export const CompanyFindManyArgsSchema: z.ZodType<Prisma.CompanyFindManyArgs> = z.object({
  select: CompanySelectSchema.optional(),
  include: CompanyIncludeSchema.optional(),
  where: CompanyWhereInputSchema.optional(),
  orderBy: z.union([ CompanyOrderByWithRelationInputSchema.array(),CompanyOrderByWithRelationInputSchema ]).optional(),
  cursor: CompanyWhereUniqueInputSchema.optional(),
  take: z.number().optional(),
  skip: z.number().optional(),
  distinct: z.union([ CompanyScalarFieldEnumSchema,CompanyScalarFieldEnumSchema.array() ]).optional(),
}).strict() ;

export const CompanyAggregateArgsSchema: z.ZodType<Prisma.CompanyAggregateArgs> = z.object({
  where: CompanyWhereInputSchema.optional(),
  orderBy: z.union([ CompanyOrderByWithRelationInputSchema.array(),CompanyOrderByWithRelationInputSchema ]).optional(),
  cursor: CompanyWhereUniqueInputSchema.optional(),
  take: z.number().optional(),
  skip: z.number().optional(),
}).strict() ;

export const CompanyGroupByArgsSchema: z.ZodType<Prisma.CompanyGroupByArgs> = z.object({
  where: CompanyWhereInputSchema.optional(),
  orderBy: z.union([ CompanyOrderByWithAggregationInputSchema.array(),CompanyOrderByWithAggregationInputSchema ]).optional(),
  by: CompanyScalarFieldEnumSchema.array(),
  having: CompanyScalarWhereWithAggregatesInputSchema.optional(),
  take: z.number().optional(),
  skip: z.number().optional(),
}).strict() ;

export const CompanyFindUniqueArgsSchema: z.ZodType<Prisma.CompanyFindUniqueArgs> = z.object({
  select: CompanySelectSchema.optional(),
  include: CompanyIncludeSchema.optional(),
  where: CompanyWhereUniqueInputSchema,
}).strict() ;

export const CompanyFindUniqueOrThrowArgsSchema: z.ZodType<Prisma.CompanyFindUniqueOrThrowArgs> = z.object({
  select: CompanySelectSchema.optional(),
  include: CompanyIncludeSchema.optional(),
  where: CompanyWhereUniqueInputSchema,
}).strict() ;

export const DocumentFindFirstArgsSchema: z.ZodType<Prisma.DocumentFindFirstArgs> = z.object({
  select: DocumentSelectSchema.optional(),
  include: DocumentIncludeSchema.optional(),
  where: DocumentWhereInputSchema.optional(),
  orderBy: z.union([ DocumentOrderByWithRelationInputSchema.array(),DocumentOrderByWithRelationInputSchema ]).optional(),
  cursor: DocumentWhereUniqueInputSchema.optional(),
  take: z.number().optional(),
  skip: z.number().optional(),
  distinct: z.union([ DocumentScalarFieldEnumSchema,DocumentScalarFieldEnumSchema.array() ]).optional(),
}).strict() ;

export const DocumentFindFirstOrThrowArgsSchema: z.ZodType<Prisma.DocumentFindFirstOrThrowArgs> = z.object({
  select: DocumentSelectSchema.optional(),
  include: DocumentIncludeSchema.optional(),
  where: DocumentWhereInputSchema.optional(),
  orderBy: z.union([ DocumentOrderByWithRelationInputSchema.array(),DocumentOrderByWithRelationInputSchema ]).optional(),
  cursor: DocumentWhereUniqueInputSchema.optional(),
  take: z.number().optional(),
  skip: z.number().optional(),
  distinct: z.union([ DocumentScalarFieldEnumSchema,DocumentScalarFieldEnumSchema.array() ]).optional(),
}).strict() ;

export const DocumentFindManyArgsSchema: z.ZodType<Prisma.DocumentFindManyArgs> = z.object({
  select: DocumentSelectSchema.optional(),
  include: DocumentIncludeSchema.optional(),
  where: DocumentWhereInputSchema.optional(),
  orderBy: z.union([ DocumentOrderByWithRelationInputSchema.array(),DocumentOrderByWithRelationInputSchema ]).optional(),
  cursor: DocumentWhereUniqueInputSchema.optional(),
  take: z.number().optional(),
  skip: z.number().optional(),
  distinct: z.union([ DocumentScalarFieldEnumSchema,DocumentScalarFieldEnumSchema.array() ]).optional(),
}).strict() ;

export const DocumentAggregateArgsSchema: z.ZodType<Prisma.DocumentAggregateArgs> = z.object({
  where: DocumentWhereInputSchema.optional(),
  orderBy: z.union([ DocumentOrderByWithRelationInputSchema.array(),DocumentOrderByWithRelationInputSchema ]).optional(),
  cursor: DocumentWhereUniqueInputSchema.optional(),
  take: z.number().optional(),
  skip: z.number().optional(),
}).strict() ;

export const DocumentGroupByArgsSchema: z.ZodType<Prisma.DocumentGroupByArgs> = z.object({
  where: DocumentWhereInputSchema.optional(),
  orderBy: z.union([ DocumentOrderByWithAggregationInputSchema.array(),DocumentOrderByWithAggregationInputSchema ]).optional(),
  by: DocumentScalarFieldEnumSchema.array(),
  having: DocumentScalarWhereWithAggregatesInputSchema.optional(),
  take: z.number().optional(),
  skip: z.number().optional(),
}).strict() ;

export const DocumentFindUniqueArgsSchema: z.ZodType<Prisma.DocumentFindUniqueArgs> = z.object({
  select: DocumentSelectSchema.optional(),
  include: DocumentIncludeSchema.optional(),
  where: DocumentWhereUniqueInputSchema,
}).strict() ;

export const DocumentFindUniqueOrThrowArgsSchema: z.ZodType<Prisma.DocumentFindUniqueOrThrowArgs> = z.object({
  select: DocumentSelectSchema.optional(),
  include: DocumentIncludeSchema.optional(),
  where: DocumentWhereUniqueInputSchema,
}).strict() ;

export const DocumentSignerFindFirstArgsSchema: z.ZodType<Prisma.DocumentSignerFindFirstArgs> = z.object({
  select: DocumentSignerSelectSchema.optional(),
  include: DocumentSignerIncludeSchema.optional(),
  where: DocumentSignerWhereInputSchema.optional(),
  orderBy: z.union([ DocumentSignerOrderByWithRelationInputSchema.array(),DocumentSignerOrderByWithRelationInputSchema ]).optional(),
  cursor: DocumentSignerWhereUniqueInputSchema.optional(),
  take: z.number().optional(),
  skip: z.number().optional(),
  distinct: z.union([ DocumentSignerScalarFieldEnumSchema,DocumentSignerScalarFieldEnumSchema.array() ]).optional(),
}).strict() ;

export const DocumentSignerFindFirstOrThrowArgsSchema: z.ZodType<Prisma.DocumentSignerFindFirstOrThrowArgs> = z.object({
  select: DocumentSignerSelectSchema.optional(),
  include: DocumentSignerIncludeSchema.optional(),
  where: DocumentSignerWhereInputSchema.optional(),
  orderBy: z.union([ DocumentSignerOrderByWithRelationInputSchema.array(),DocumentSignerOrderByWithRelationInputSchema ]).optional(),
  cursor: DocumentSignerWhereUniqueInputSchema.optional(),
  take: z.number().optional(),
  skip: z.number().optional(),
  distinct: z.union([ DocumentSignerScalarFieldEnumSchema,DocumentSignerScalarFieldEnumSchema.array() ]).optional(),
}).strict() ;

export const DocumentSignerFindManyArgsSchema: z.ZodType<Prisma.DocumentSignerFindManyArgs> = z.object({
  select: DocumentSignerSelectSchema.optional(),
  include: DocumentSignerIncludeSchema.optional(),
  where: DocumentSignerWhereInputSchema.optional(),
  orderBy: z.union([ DocumentSignerOrderByWithRelationInputSchema.array(),DocumentSignerOrderByWithRelationInputSchema ]).optional(),
  cursor: DocumentSignerWhereUniqueInputSchema.optional(),
  take: z.number().optional(),
  skip: z.number().optional(),
  distinct: z.union([ DocumentSignerScalarFieldEnumSchema,DocumentSignerScalarFieldEnumSchema.array() ]).optional(),
}).strict() ;

export const DocumentSignerAggregateArgsSchema: z.ZodType<Prisma.DocumentSignerAggregateArgs> = z.object({
  where: DocumentSignerWhereInputSchema.optional(),
  orderBy: z.union([ DocumentSignerOrderByWithRelationInputSchema.array(),DocumentSignerOrderByWithRelationInputSchema ]).optional(),
  cursor: DocumentSignerWhereUniqueInputSchema.optional(),
  take: z.number().optional(),
  skip: z.number().optional(),
}).strict() ;

export const DocumentSignerGroupByArgsSchema: z.ZodType<Prisma.DocumentSignerGroupByArgs> = z.object({
  where: DocumentSignerWhereInputSchema.optional(),
  orderBy: z.union([ DocumentSignerOrderByWithAggregationInputSchema.array(),DocumentSignerOrderByWithAggregationInputSchema ]).optional(),
  by: DocumentSignerScalarFieldEnumSchema.array(),
  having: DocumentSignerScalarWhereWithAggregatesInputSchema.optional(),
  take: z.number().optional(),
  skip: z.number().optional(),
}).strict() ;

export const DocumentSignerFindUniqueArgsSchema: z.ZodType<Prisma.DocumentSignerFindUniqueArgs> = z.object({
  select: DocumentSignerSelectSchema.optional(),
  include: DocumentSignerIncludeSchema.optional(),
  where: DocumentSignerWhereUniqueInputSchema,
}).strict() ;

export const DocumentSignerFindUniqueOrThrowArgsSchema: z.ZodType<Prisma.DocumentSignerFindUniqueOrThrowArgs> = z.object({
  select: DocumentSignerSelectSchema.optional(),
  include: DocumentSignerIncludeSchema.optional(),
  where: DocumentSignerWhereUniqueInputSchema,
}).strict() ;

export const SignatureFieldFindFirstArgsSchema: z.ZodType<Prisma.SignatureFieldFindFirstArgs> = z.object({
  select: SignatureFieldSelectSchema.optional(),
  include: SignatureFieldIncludeSchema.optional(),
  where: SignatureFieldWhereInputSchema.optional(),
  orderBy: z.union([ SignatureFieldOrderByWithRelationInputSchema.array(),SignatureFieldOrderByWithRelationInputSchema ]).optional(),
  cursor: SignatureFieldWhereUniqueInputSchema.optional(),
  take: z.number().optional(),
  skip: z.number().optional(),
  distinct: z.union([ SignatureFieldScalarFieldEnumSchema,SignatureFieldScalarFieldEnumSchema.array() ]).optional(),
}).strict() ;

export const SignatureFieldFindFirstOrThrowArgsSchema: z.ZodType<Prisma.SignatureFieldFindFirstOrThrowArgs> = z.object({
  select: SignatureFieldSelectSchema.optional(),
  include: SignatureFieldIncludeSchema.optional(),
  where: SignatureFieldWhereInputSchema.optional(),
  orderBy: z.union([ SignatureFieldOrderByWithRelationInputSchema.array(),SignatureFieldOrderByWithRelationInputSchema ]).optional(),
  cursor: SignatureFieldWhereUniqueInputSchema.optional(),
  take: z.number().optional(),
  skip: z.number().optional(),
  distinct: z.union([ SignatureFieldScalarFieldEnumSchema,SignatureFieldScalarFieldEnumSchema.array() ]).optional(),
}).strict() ;

export const SignatureFieldFindManyArgsSchema: z.ZodType<Prisma.SignatureFieldFindManyArgs> = z.object({
  select: SignatureFieldSelectSchema.optional(),
  include: SignatureFieldIncludeSchema.optional(),
  where: SignatureFieldWhereInputSchema.optional(),
  orderBy: z.union([ SignatureFieldOrderByWithRelationInputSchema.array(),SignatureFieldOrderByWithRelationInputSchema ]).optional(),
  cursor: SignatureFieldWhereUniqueInputSchema.optional(),
  take: z.number().optional(),
  skip: z.number().optional(),
  distinct: z.union([ SignatureFieldScalarFieldEnumSchema,SignatureFieldScalarFieldEnumSchema.array() ]).optional(),
}).strict() ;

export const SignatureFieldAggregateArgsSchema: z.ZodType<Prisma.SignatureFieldAggregateArgs> = z.object({
  where: SignatureFieldWhereInputSchema.optional(),
  orderBy: z.union([ SignatureFieldOrderByWithRelationInputSchema.array(),SignatureFieldOrderByWithRelationInputSchema ]).optional(),
  cursor: SignatureFieldWhereUniqueInputSchema.optional(),
  take: z.number().optional(),
  skip: z.number().optional(),
}).strict() ;

export const SignatureFieldGroupByArgsSchema: z.ZodType<Prisma.SignatureFieldGroupByArgs> = z.object({
  where: SignatureFieldWhereInputSchema.optional(),
  orderBy: z.union([ SignatureFieldOrderByWithAggregationInputSchema.array(),SignatureFieldOrderByWithAggregationInputSchema ]).optional(),
  by: SignatureFieldScalarFieldEnumSchema.array(),
  having: SignatureFieldScalarWhereWithAggregatesInputSchema.optional(),
  take: z.number().optional(),
  skip: z.number().optional(),
}).strict() ;

export const SignatureFieldFindUniqueArgsSchema: z.ZodType<Prisma.SignatureFieldFindUniqueArgs> = z.object({
  select: SignatureFieldSelectSchema.optional(),
  include: SignatureFieldIncludeSchema.optional(),
  where: SignatureFieldWhereUniqueInputSchema,
}).strict() ;

export const SignatureFieldFindUniqueOrThrowArgsSchema: z.ZodType<Prisma.SignatureFieldFindUniqueOrThrowArgs> = z.object({
  select: SignatureFieldSelectSchema.optional(),
  include: SignatureFieldIncludeSchema.optional(),
  where: SignatureFieldWhereUniqueInputSchema,
}).strict() ;

export const SignatureFindFirstArgsSchema: z.ZodType<Prisma.SignatureFindFirstArgs> = z.object({
  select: SignatureSelectSchema.optional(),
  include: SignatureIncludeSchema.optional(),
  where: SignatureWhereInputSchema.optional(),
  orderBy: z.union([ SignatureOrderByWithRelationInputSchema.array(),SignatureOrderByWithRelationInputSchema ]).optional(),
  cursor: SignatureWhereUniqueInputSchema.optional(),
  take: z.number().optional(),
  skip: z.number().optional(),
  distinct: z.union([ SignatureScalarFieldEnumSchema,SignatureScalarFieldEnumSchema.array() ]).optional(),
}).strict() ;

export const SignatureFindFirstOrThrowArgsSchema: z.ZodType<Prisma.SignatureFindFirstOrThrowArgs> = z.object({
  select: SignatureSelectSchema.optional(),
  include: SignatureIncludeSchema.optional(),
  where: SignatureWhereInputSchema.optional(),
  orderBy: z.union([ SignatureOrderByWithRelationInputSchema.array(),SignatureOrderByWithRelationInputSchema ]).optional(),
  cursor: SignatureWhereUniqueInputSchema.optional(),
  take: z.number().optional(),
  skip: z.number().optional(),
  distinct: z.union([ SignatureScalarFieldEnumSchema,SignatureScalarFieldEnumSchema.array() ]).optional(),
}).strict() ;

export const SignatureFindManyArgsSchema: z.ZodType<Prisma.SignatureFindManyArgs> = z.object({
  select: SignatureSelectSchema.optional(),
  include: SignatureIncludeSchema.optional(),
  where: SignatureWhereInputSchema.optional(),
  orderBy: z.union([ SignatureOrderByWithRelationInputSchema.array(),SignatureOrderByWithRelationInputSchema ]).optional(),
  cursor: SignatureWhereUniqueInputSchema.optional(),
  take: z.number().optional(),
  skip: z.number().optional(),
  distinct: z.union([ SignatureScalarFieldEnumSchema,SignatureScalarFieldEnumSchema.array() ]).optional(),
}).strict() ;

export const SignatureAggregateArgsSchema: z.ZodType<Prisma.SignatureAggregateArgs> = z.object({
  where: SignatureWhereInputSchema.optional(),
  orderBy: z.union([ SignatureOrderByWithRelationInputSchema.array(),SignatureOrderByWithRelationInputSchema ]).optional(),
  cursor: SignatureWhereUniqueInputSchema.optional(),
  take: z.number().optional(),
  skip: z.number().optional(),
}).strict() ;

export const SignatureGroupByArgsSchema: z.ZodType<Prisma.SignatureGroupByArgs> = z.object({
  where: SignatureWhereInputSchema.optional(),
  orderBy: z.union([ SignatureOrderByWithAggregationInputSchema.array(),SignatureOrderByWithAggregationInputSchema ]).optional(),
  by: SignatureScalarFieldEnumSchema.array(),
  having: SignatureScalarWhereWithAggregatesInputSchema.optional(),
  take: z.number().optional(),
  skip: z.number().optional(),
}).strict() ;

export const SignatureFindUniqueArgsSchema: z.ZodType<Prisma.SignatureFindUniqueArgs> = z.object({
  select: SignatureSelectSchema.optional(),
  include: SignatureIncludeSchema.optional(),
  where: SignatureWhereUniqueInputSchema,
}).strict() ;

export const SignatureFindUniqueOrThrowArgsSchema: z.ZodType<Prisma.SignatureFindUniqueOrThrowArgs> = z.object({
  select: SignatureSelectSchema.optional(),
  include: SignatureIncludeSchema.optional(),
  where: SignatureWhereUniqueInputSchema,
}).strict() ;

export const CertificateFindFirstArgsSchema: z.ZodType<Prisma.CertificateFindFirstArgs> = z.object({
  select: CertificateSelectSchema.optional(),
  include: CertificateIncludeSchema.optional(),
  where: CertificateWhereInputSchema.optional(),
  orderBy: z.union([ CertificateOrderByWithRelationInputSchema.array(),CertificateOrderByWithRelationInputSchema ]).optional(),
  cursor: CertificateWhereUniqueInputSchema.optional(),
  take: z.number().optional(),
  skip: z.number().optional(),
  distinct: z.union([ CertificateScalarFieldEnumSchema,CertificateScalarFieldEnumSchema.array() ]).optional(),
}).strict() ;

export const CertificateFindFirstOrThrowArgsSchema: z.ZodType<Prisma.CertificateFindFirstOrThrowArgs> = z.object({
  select: CertificateSelectSchema.optional(),
  include: CertificateIncludeSchema.optional(),
  where: CertificateWhereInputSchema.optional(),
  orderBy: z.union([ CertificateOrderByWithRelationInputSchema.array(),CertificateOrderByWithRelationInputSchema ]).optional(),
  cursor: CertificateWhereUniqueInputSchema.optional(),
  take: z.number().optional(),
  skip: z.number().optional(),
  distinct: z.union([ CertificateScalarFieldEnumSchema,CertificateScalarFieldEnumSchema.array() ]).optional(),
}).strict() ;

export const CertificateFindManyArgsSchema: z.ZodType<Prisma.CertificateFindManyArgs> = z.object({
  select: CertificateSelectSchema.optional(),
  include: CertificateIncludeSchema.optional(),
  where: CertificateWhereInputSchema.optional(),
  orderBy: z.union([ CertificateOrderByWithRelationInputSchema.array(),CertificateOrderByWithRelationInputSchema ]).optional(),
  cursor: CertificateWhereUniqueInputSchema.optional(),
  take: z.number().optional(),
  skip: z.number().optional(),
  distinct: z.union([ CertificateScalarFieldEnumSchema,CertificateScalarFieldEnumSchema.array() ]).optional(),
}).strict() ;

export const CertificateAggregateArgsSchema: z.ZodType<Prisma.CertificateAggregateArgs> = z.object({
  where: CertificateWhereInputSchema.optional(),
  orderBy: z.union([ CertificateOrderByWithRelationInputSchema.array(),CertificateOrderByWithRelationInputSchema ]).optional(),
  cursor: CertificateWhereUniqueInputSchema.optional(),
  take: z.number().optional(),
  skip: z.number().optional(),
}).strict() ;

export const CertificateGroupByArgsSchema: z.ZodType<Prisma.CertificateGroupByArgs> = z.object({
  where: CertificateWhereInputSchema.optional(),
  orderBy: z.union([ CertificateOrderByWithAggregationInputSchema.array(),CertificateOrderByWithAggregationInputSchema ]).optional(),
  by: CertificateScalarFieldEnumSchema.array(),
  having: CertificateScalarWhereWithAggregatesInputSchema.optional(),
  take: z.number().optional(),
  skip: z.number().optional(),
}).strict() ;

export const CertificateFindUniqueArgsSchema: z.ZodType<Prisma.CertificateFindUniqueArgs> = z.object({
  select: CertificateSelectSchema.optional(),
  include: CertificateIncludeSchema.optional(),
  where: CertificateWhereUniqueInputSchema,
}).strict() ;

export const CertificateFindUniqueOrThrowArgsSchema: z.ZodType<Prisma.CertificateFindUniqueOrThrowArgs> = z.object({
  select: CertificateSelectSchema.optional(),
  include: CertificateIncludeSchema.optional(),
  where: CertificateWhereUniqueInputSchema,
}).strict() ;

export const SigningTemplateFindFirstArgsSchema: z.ZodType<Prisma.SigningTemplateFindFirstArgs> = z.object({
  select: SigningTemplateSelectSchema.optional(),
  include: SigningTemplateIncludeSchema.optional(),
  where: SigningTemplateWhereInputSchema.optional(),
  orderBy: z.union([ SigningTemplateOrderByWithRelationInputSchema.array(),SigningTemplateOrderByWithRelationInputSchema ]).optional(),
  cursor: SigningTemplateWhereUniqueInputSchema.optional(),
  take: z.number().optional(),
  skip: z.number().optional(),
  distinct: z.union([ SigningTemplateScalarFieldEnumSchema,SigningTemplateScalarFieldEnumSchema.array() ]).optional(),
}).strict() ;

export const SigningTemplateFindFirstOrThrowArgsSchema: z.ZodType<Prisma.SigningTemplateFindFirstOrThrowArgs> = z.object({
  select: SigningTemplateSelectSchema.optional(),
  include: SigningTemplateIncludeSchema.optional(),
  where: SigningTemplateWhereInputSchema.optional(),
  orderBy: z.union([ SigningTemplateOrderByWithRelationInputSchema.array(),SigningTemplateOrderByWithRelationInputSchema ]).optional(),
  cursor: SigningTemplateWhereUniqueInputSchema.optional(),
  take: z.number().optional(),
  skip: z.number().optional(),
  distinct: z.union([ SigningTemplateScalarFieldEnumSchema,SigningTemplateScalarFieldEnumSchema.array() ]).optional(),
}).strict() ;

export const SigningTemplateFindManyArgsSchema: z.ZodType<Prisma.SigningTemplateFindManyArgs> = z.object({
  select: SigningTemplateSelectSchema.optional(),
  include: SigningTemplateIncludeSchema.optional(),
  where: SigningTemplateWhereInputSchema.optional(),
  orderBy: z.union([ SigningTemplateOrderByWithRelationInputSchema.array(),SigningTemplateOrderByWithRelationInputSchema ]).optional(),
  cursor: SigningTemplateWhereUniqueInputSchema.optional(),
  take: z.number().optional(),
  skip: z.number().optional(),
  distinct: z.union([ SigningTemplateScalarFieldEnumSchema,SigningTemplateScalarFieldEnumSchema.array() ]).optional(),
}).strict() ;

export const SigningTemplateAggregateArgsSchema: z.ZodType<Prisma.SigningTemplateAggregateArgs> = z.object({
  where: SigningTemplateWhereInputSchema.optional(),
  orderBy: z.union([ SigningTemplateOrderByWithRelationInputSchema.array(),SigningTemplateOrderByWithRelationInputSchema ]).optional(),
  cursor: SigningTemplateWhereUniqueInputSchema.optional(),
  take: z.number().optional(),
  skip: z.number().optional(),
}).strict() ;

export const SigningTemplateGroupByArgsSchema: z.ZodType<Prisma.SigningTemplateGroupByArgs> = z.object({
  where: SigningTemplateWhereInputSchema.optional(),
  orderBy: z.union([ SigningTemplateOrderByWithAggregationInputSchema.array(),SigningTemplateOrderByWithAggregationInputSchema ]).optional(),
  by: SigningTemplateScalarFieldEnumSchema.array(),
  having: SigningTemplateScalarWhereWithAggregatesInputSchema.optional(),
  take: z.number().optional(),
  skip: z.number().optional(),
}).strict() ;

export const SigningTemplateFindUniqueArgsSchema: z.ZodType<Prisma.SigningTemplateFindUniqueArgs> = z.object({
  select: SigningTemplateSelectSchema.optional(),
  include: SigningTemplateIncludeSchema.optional(),
  where: SigningTemplateWhereUniqueInputSchema,
}).strict() ;

export const SigningTemplateFindUniqueOrThrowArgsSchema: z.ZodType<Prisma.SigningTemplateFindUniqueOrThrowArgs> = z.object({
  select: SigningTemplateSelectSchema.optional(),
  include: SigningTemplateIncludeSchema.optional(),
  where: SigningTemplateWhereUniqueInputSchema,
}).strict() ;

export const BlockchainWalletFindFirstArgsSchema: z.ZodType<Prisma.BlockchainWalletFindFirstArgs> = z.object({
  select: BlockchainWalletSelectSchema.optional(),
  include: BlockchainWalletIncludeSchema.optional(),
  where: BlockchainWalletWhereInputSchema.optional(),
  orderBy: z.union([ BlockchainWalletOrderByWithRelationInputSchema.array(),BlockchainWalletOrderByWithRelationInputSchema ]).optional(),
  cursor: BlockchainWalletWhereUniqueInputSchema.optional(),
  take: z.number().optional(),
  skip: z.number().optional(),
  distinct: z.union([ BlockchainWalletScalarFieldEnumSchema,BlockchainWalletScalarFieldEnumSchema.array() ]).optional(),
}).strict() ;

export const BlockchainWalletFindFirstOrThrowArgsSchema: z.ZodType<Prisma.BlockchainWalletFindFirstOrThrowArgs> = z.object({
  select: BlockchainWalletSelectSchema.optional(),
  include: BlockchainWalletIncludeSchema.optional(),
  where: BlockchainWalletWhereInputSchema.optional(),
  orderBy: z.union([ BlockchainWalletOrderByWithRelationInputSchema.array(),BlockchainWalletOrderByWithRelationInputSchema ]).optional(),
  cursor: BlockchainWalletWhereUniqueInputSchema.optional(),
  take: z.number().optional(),
  skip: z.number().optional(),
  distinct: z.union([ BlockchainWalletScalarFieldEnumSchema,BlockchainWalletScalarFieldEnumSchema.array() ]).optional(),
}).strict() ;

export const BlockchainWalletFindManyArgsSchema: z.ZodType<Prisma.BlockchainWalletFindManyArgs> = z.object({
  select: BlockchainWalletSelectSchema.optional(),
  include: BlockchainWalletIncludeSchema.optional(),
  where: BlockchainWalletWhereInputSchema.optional(),
  orderBy: z.union([ BlockchainWalletOrderByWithRelationInputSchema.array(),BlockchainWalletOrderByWithRelationInputSchema ]).optional(),
  cursor: BlockchainWalletWhereUniqueInputSchema.optional(),
  take: z.number().optional(),
  skip: z.number().optional(),
  distinct: z.union([ BlockchainWalletScalarFieldEnumSchema,BlockchainWalletScalarFieldEnumSchema.array() ]).optional(),
}).strict() ;

export const BlockchainWalletAggregateArgsSchema: z.ZodType<Prisma.BlockchainWalletAggregateArgs> = z.object({
  where: BlockchainWalletWhereInputSchema.optional(),
  orderBy: z.union([ BlockchainWalletOrderByWithRelationInputSchema.array(),BlockchainWalletOrderByWithRelationInputSchema ]).optional(),
  cursor: BlockchainWalletWhereUniqueInputSchema.optional(),
  take: z.number().optional(),
  skip: z.number().optional(),
}).strict() ;

export const BlockchainWalletGroupByArgsSchema: z.ZodType<Prisma.BlockchainWalletGroupByArgs> = z.object({
  where: BlockchainWalletWhereInputSchema.optional(),
  orderBy: z.union([ BlockchainWalletOrderByWithAggregationInputSchema.array(),BlockchainWalletOrderByWithAggregationInputSchema ]).optional(),
  by: BlockchainWalletScalarFieldEnumSchema.array(),
  having: BlockchainWalletScalarWhereWithAggregatesInputSchema.optional(),
  take: z.number().optional(),
  skip: z.number().optional(),
}).strict() ;

export const BlockchainWalletFindUniqueArgsSchema: z.ZodType<Prisma.BlockchainWalletFindUniqueArgs> = z.object({
  select: BlockchainWalletSelectSchema.optional(),
  include: BlockchainWalletIncludeSchema.optional(),
  where: BlockchainWalletWhereUniqueInputSchema,
}).strict() ;

export const BlockchainWalletFindUniqueOrThrowArgsSchema: z.ZodType<Prisma.BlockchainWalletFindUniqueOrThrowArgs> = z.object({
  select: BlockchainWalletSelectSchema.optional(),
  include: BlockchainWalletIncludeSchema.optional(),
  where: BlockchainWalletWhereUniqueInputSchema,
}).strict() ;

export const ApiKeyFindFirstArgsSchema: z.ZodType<Prisma.ApiKeyFindFirstArgs> = z.object({
  select: ApiKeySelectSchema.optional(),
  include: ApiKeyIncludeSchema.optional(),
  where: ApiKeyWhereInputSchema.optional(),
  orderBy: z.union([ ApiKeyOrderByWithRelationInputSchema.array(),ApiKeyOrderByWithRelationInputSchema ]).optional(),
  cursor: ApiKeyWhereUniqueInputSchema.optional(),
  take: z.number().optional(),
  skip: z.number().optional(),
  distinct: z.union([ ApiKeyScalarFieldEnumSchema,ApiKeyScalarFieldEnumSchema.array() ]).optional(),
}).strict() ;

export const ApiKeyFindFirstOrThrowArgsSchema: z.ZodType<Prisma.ApiKeyFindFirstOrThrowArgs> = z.object({
  select: ApiKeySelectSchema.optional(),
  include: ApiKeyIncludeSchema.optional(),
  where: ApiKeyWhereInputSchema.optional(),
  orderBy: z.union([ ApiKeyOrderByWithRelationInputSchema.array(),ApiKeyOrderByWithRelationInputSchema ]).optional(),
  cursor: ApiKeyWhereUniqueInputSchema.optional(),
  take: z.number().optional(),
  skip: z.number().optional(),
  distinct: z.union([ ApiKeyScalarFieldEnumSchema,ApiKeyScalarFieldEnumSchema.array() ]).optional(),
}).strict() ;

export const ApiKeyFindManyArgsSchema: z.ZodType<Prisma.ApiKeyFindManyArgs> = z.object({
  select: ApiKeySelectSchema.optional(),
  include: ApiKeyIncludeSchema.optional(),
  where: ApiKeyWhereInputSchema.optional(),
  orderBy: z.union([ ApiKeyOrderByWithRelationInputSchema.array(),ApiKeyOrderByWithRelationInputSchema ]).optional(),
  cursor: ApiKeyWhereUniqueInputSchema.optional(),
  take: z.number().optional(),
  skip: z.number().optional(),
  distinct: z.union([ ApiKeyScalarFieldEnumSchema,ApiKeyScalarFieldEnumSchema.array() ]).optional(),
}).strict() ;

export const ApiKeyAggregateArgsSchema: z.ZodType<Prisma.ApiKeyAggregateArgs> = z.object({
  where: ApiKeyWhereInputSchema.optional(),
  orderBy: z.union([ ApiKeyOrderByWithRelationInputSchema.array(),ApiKeyOrderByWithRelationInputSchema ]).optional(),
  cursor: ApiKeyWhereUniqueInputSchema.optional(),
  take: z.number().optional(),
  skip: z.number().optional(),
}).strict() ;

export const ApiKeyGroupByArgsSchema: z.ZodType<Prisma.ApiKeyGroupByArgs> = z.object({
  where: ApiKeyWhereInputSchema.optional(),
  orderBy: z.union([ ApiKeyOrderByWithAggregationInputSchema.array(),ApiKeyOrderByWithAggregationInputSchema ]).optional(),
  by: ApiKeyScalarFieldEnumSchema.array(),
  having: ApiKeyScalarWhereWithAggregatesInputSchema.optional(),
  take: z.number().optional(),
  skip: z.number().optional(),
}).strict() ;

export const ApiKeyFindUniqueArgsSchema: z.ZodType<Prisma.ApiKeyFindUniqueArgs> = z.object({
  select: ApiKeySelectSchema.optional(),
  include: ApiKeyIncludeSchema.optional(),
  where: ApiKeyWhereUniqueInputSchema,
}).strict() ;

export const ApiKeyFindUniqueOrThrowArgsSchema: z.ZodType<Prisma.ApiKeyFindUniqueOrThrowArgs> = z.object({
  select: ApiKeySelectSchema.optional(),
  include: ApiKeyIncludeSchema.optional(),
  where: ApiKeyWhereUniqueInputSchema,
}).strict() ;

export const AuditLogFindFirstArgsSchema: z.ZodType<Prisma.AuditLogFindFirstArgs> = z.object({
  select: AuditLogSelectSchema.optional(),
  include: AuditLogIncludeSchema.optional(),
  where: AuditLogWhereInputSchema.optional(),
  orderBy: z.union([ AuditLogOrderByWithRelationInputSchema.array(),AuditLogOrderByWithRelationInputSchema ]).optional(),
  cursor: AuditLogWhereUniqueInputSchema.optional(),
  take: z.number().optional(),
  skip: z.number().optional(),
  distinct: z.union([ AuditLogScalarFieldEnumSchema,AuditLogScalarFieldEnumSchema.array() ]).optional(),
}).strict() ;

export const AuditLogFindFirstOrThrowArgsSchema: z.ZodType<Prisma.AuditLogFindFirstOrThrowArgs> = z.object({
  select: AuditLogSelectSchema.optional(),
  include: AuditLogIncludeSchema.optional(),
  where: AuditLogWhereInputSchema.optional(),
  orderBy: z.union([ AuditLogOrderByWithRelationInputSchema.array(),AuditLogOrderByWithRelationInputSchema ]).optional(),
  cursor: AuditLogWhereUniqueInputSchema.optional(),
  take: z.number().optional(),
  skip: z.number().optional(),
  distinct: z.union([ AuditLogScalarFieldEnumSchema,AuditLogScalarFieldEnumSchema.array() ]).optional(),
}).strict() ;

export const AuditLogFindManyArgsSchema: z.ZodType<Prisma.AuditLogFindManyArgs> = z.object({
  select: AuditLogSelectSchema.optional(),
  include: AuditLogIncludeSchema.optional(),
  where: AuditLogWhereInputSchema.optional(),
  orderBy: z.union([ AuditLogOrderByWithRelationInputSchema.array(),AuditLogOrderByWithRelationInputSchema ]).optional(),
  cursor: AuditLogWhereUniqueInputSchema.optional(),
  take: z.number().optional(),
  skip: z.number().optional(),
  distinct: z.union([ AuditLogScalarFieldEnumSchema,AuditLogScalarFieldEnumSchema.array() ]).optional(),
}).strict() ;

export const AuditLogAggregateArgsSchema: z.ZodType<Prisma.AuditLogAggregateArgs> = z.object({
  where: AuditLogWhereInputSchema.optional(),
  orderBy: z.union([ AuditLogOrderByWithRelationInputSchema.array(),AuditLogOrderByWithRelationInputSchema ]).optional(),
  cursor: AuditLogWhereUniqueInputSchema.optional(),
  take: z.number().optional(),
  skip: z.number().optional(),
}).strict() ;

export const AuditLogGroupByArgsSchema: z.ZodType<Prisma.AuditLogGroupByArgs> = z.object({
  where: AuditLogWhereInputSchema.optional(),
  orderBy: z.union([ AuditLogOrderByWithAggregationInputSchema.array(),AuditLogOrderByWithAggregationInputSchema ]).optional(),
  by: AuditLogScalarFieldEnumSchema.array(),
  having: AuditLogScalarWhereWithAggregatesInputSchema.optional(),
  take: z.number().optional(),
  skip: z.number().optional(),
}).strict() ;

export const AuditLogFindUniqueArgsSchema: z.ZodType<Prisma.AuditLogFindUniqueArgs> = z.object({
  select: AuditLogSelectSchema.optional(),
  include: AuditLogIncludeSchema.optional(),
  where: AuditLogWhereUniqueInputSchema,
}).strict() ;

export const AuditLogFindUniqueOrThrowArgsSchema: z.ZodType<Prisma.AuditLogFindUniqueOrThrowArgs> = z.object({
  select: AuditLogSelectSchema.optional(),
  include: AuditLogIncludeSchema.optional(),
  where: AuditLogWhereUniqueInputSchema,
}).strict() ;

export const UserCreateArgsSchema: z.ZodType<Prisma.UserCreateArgs> = z.object({
  select: UserSelectSchema.optional(),
  include: UserIncludeSchema.optional(),
  data: z.union([ UserCreateInputSchema,UserUncheckedCreateInputSchema ]),
}).strict() ;

export const UserUpsertArgsSchema: z.ZodType<Prisma.UserUpsertArgs> = z.object({
  select: UserSelectSchema.optional(),
  include: UserIncludeSchema.optional(),
  where: UserWhereUniqueInputSchema,
  create: z.union([ UserCreateInputSchema,UserUncheckedCreateInputSchema ]),
  update: z.union([ UserUpdateInputSchema,UserUncheckedUpdateInputSchema ]),
}).strict() ;

export const UserCreateManyArgsSchema: z.ZodType<Prisma.UserCreateManyArgs> = z.object({
  data: z.union([ UserCreateManyInputSchema,UserCreateManyInputSchema.array() ]),
  skipDuplicates: z.boolean().optional(),
}).strict() ;

export const UserCreateManyAndReturnArgsSchema: z.ZodType<Prisma.UserCreateManyAndReturnArgs> = z.object({
  data: z.union([ UserCreateManyInputSchema,UserCreateManyInputSchema.array() ]),
  skipDuplicates: z.boolean().optional(),
}).strict() ;

export const UserDeleteArgsSchema: z.ZodType<Prisma.UserDeleteArgs> = z.object({
  select: UserSelectSchema.optional(),
  include: UserIncludeSchema.optional(),
  where: UserWhereUniqueInputSchema,
}).strict() ;

export const UserUpdateArgsSchema: z.ZodType<Prisma.UserUpdateArgs> = z.object({
  select: UserSelectSchema.optional(),
  include: UserIncludeSchema.optional(),
  data: z.union([ UserUpdateInputSchema,UserUncheckedUpdateInputSchema ]),
  where: UserWhereUniqueInputSchema,
}).strict() ;

export const UserUpdateManyArgsSchema: z.ZodType<Prisma.UserUpdateManyArgs> = z.object({
  data: z.union([ UserUpdateManyMutationInputSchema,UserUncheckedUpdateManyInputSchema ]),
  where: UserWhereInputSchema.optional(),
}).strict() ;

export const updateManyUserCreateManyAndReturnArgsSchema: z.ZodType<Prisma.updateManyUserCreateManyAndReturnArgs> = z.object({
  data: z.union([ UserUpdateManyMutationInputSchema,UserUncheckedUpdateManyInputSchema ]),
  where: UserWhereInputSchema.optional(),
}).strict() ;

export const UserDeleteManyArgsSchema: z.ZodType<Prisma.UserDeleteManyArgs> = z.object({
  where: UserWhereInputSchema.optional(),
}).strict() ;

export const CompanyCreateArgsSchema: z.ZodType<Prisma.CompanyCreateArgs> = z.object({
  select: CompanySelectSchema.optional(),
  include: CompanyIncludeSchema.optional(),
  data: z.union([ CompanyCreateInputSchema,CompanyUncheckedCreateInputSchema ]),
}).strict() ;

export const CompanyUpsertArgsSchema: z.ZodType<Prisma.CompanyUpsertArgs> = z.object({
  select: CompanySelectSchema.optional(),
  include: CompanyIncludeSchema.optional(),
  where: CompanyWhereUniqueInputSchema,
  create: z.union([ CompanyCreateInputSchema,CompanyUncheckedCreateInputSchema ]),
  update: z.union([ CompanyUpdateInputSchema,CompanyUncheckedUpdateInputSchema ]),
}).strict() ;

export const CompanyCreateManyArgsSchema: z.ZodType<Prisma.CompanyCreateManyArgs> = z.object({
  data: z.union([ CompanyCreateManyInputSchema,CompanyCreateManyInputSchema.array() ]),
  skipDuplicates: z.boolean().optional(),
}).strict() ;

export const CompanyCreateManyAndReturnArgsSchema: z.ZodType<Prisma.CompanyCreateManyAndReturnArgs> = z.object({
  data: z.union([ CompanyCreateManyInputSchema,CompanyCreateManyInputSchema.array() ]),
  skipDuplicates: z.boolean().optional(),
}).strict() ;

export const CompanyDeleteArgsSchema: z.ZodType<Prisma.CompanyDeleteArgs> = z.object({
  select: CompanySelectSchema.optional(),
  include: CompanyIncludeSchema.optional(),
  where: CompanyWhereUniqueInputSchema,
}).strict() ;

export const CompanyUpdateArgsSchema: z.ZodType<Prisma.CompanyUpdateArgs> = z.object({
  select: CompanySelectSchema.optional(),
  include: CompanyIncludeSchema.optional(),
  data: z.union([ CompanyUpdateInputSchema,CompanyUncheckedUpdateInputSchema ]),
  where: CompanyWhereUniqueInputSchema,
}).strict() ;

export const CompanyUpdateManyArgsSchema: z.ZodType<Prisma.CompanyUpdateManyArgs> = z.object({
  data: z.union([ CompanyUpdateManyMutationInputSchema,CompanyUncheckedUpdateManyInputSchema ]),
  where: CompanyWhereInputSchema.optional(),
}).strict() ;

export const updateManyCompanyCreateManyAndReturnArgsSchema: z.ZodType<Prisma.updateManyCompanyCreateManyAndReturnArgs> = z.object({
  data: z.union([ CompanyUpdateManyMutationInputSchema,CompanyUncheckedUpdateManyInputSchema ]),
  where: CompanyWhereInputSchema.optional(),
}).strict() ;

export const CompanyDeleteManyArgsSchema: z.ZodType<Prisma.CompanyDeleteManyArgs> = z.object({
  where: CompanyWhereInputSchema.optional(),
}).strict() ;

export const DocumentCreateArgsSchema: z.ZodType<Prisma.DocumentCreateArgs> = z.object({
  select: DocumentSelectSchema.optional(),
  include: DocumentIncludeSchema.optional(),
  data: z.union([ DocumentCreateInputSchema,DocumentUncheckedCreateInputSchema ]),
}).strict() ;

export const DocumentUpsertArgsSchema: z.ZodType<Prisma.DocumentUpsertArgs> = z.object({
  select: DocumentSelectSchema.optional(),
  include: DocumentIncludeSchema.optional(),
  where: DocumentWhereUniqueInputSchema,
  create: z.union([ DocumentCreateInputSchema,DocumentUncheckedCreateInputSchema ]),
  update: z.union([ DocumentUpdateInputSchema,DocumentUncheckedUpdateInputSchema ]),
}).strict() ;

export const DocumentCreateManyArgsSchema: z.ZodType<Prisma.DocumentCreateManyArgs> = z.object({
  data: z.union([ DocumentCreateManyInputSchema,DocumentCreateManyInputSchema.array() ]),
  skipDuplicates: z.boolean().optional(),
}).strict() ;

export const DocumentCreateManyAndReturnArgsSchema: z.ZodType<Prisma.DocumentCreateManyAndReturnArgs> = z.object({
  data: z.union([ DocumentCreateManyInputSchema,DocumentCreateManyInputSchema.array() ]),
  skipDuplicates: z.boolean().optional(),
}).strict() ;

export const DocumentDeleteArgsSchema: z.ZodType<Prisma.DocumentDeleteArgs> = z.object({
  select: DocumentSelectSchema.optional(),
  include: DocumentIncludeSchema.optional(),
  where: DocumentWhereUniqueInputSchema,
}).strict() ;

export const DocumentUpdateArgsSchema: z.ZodType<Prisma.DocumentUpdateArgs> = z.object({
  select: DocumentSelectSchema.optional(),
  include: DocumentIncludeSchema.optional(),
  data: z.union([ DocumentUpdateInputSchema,DocumentUncheckedUpdateInputSchema ]),
  where: DocumentWhereUniqueInputSchema,
}).strict() ;

export const DocumentUpdateManyArgsSchema: z.ZodType<Prisma.DocumentUpdateManyArgs> = z.object({
  data: z.union([ DocumentUpdateManyMutationInputSchema,DocumentUncheckedUpdateManyInputSchema ]),
  where: DocumentWhereInputSchema.optional(),
}).strict() ;

export const updateManyDocumentCreateManyAndReturnArgsSchema: z.ZodType<Prisma.updateManyDocumentCreateManyAndReturnArgs> = z.object({
  data: z.union([ DocumentUpdateManyMutationInputSchema,DocumentUncheckedUpdateManyInputSchema ]),
  where: DocumentWhereInputSchema.optional(),
}).strict() ;

export const DocumentDeleteManyArgsSchema: z.ZodType<Prisma.DocumentDeleteManyArgs> = z.object({
  where: DocumentWhereInputSchema.optional(),
}).strict() ;

export const DocumentSignerCreateArgsSchema: z.ZodType<Prisma.DocumentSignerCreateArgs> = z.object({
  select: DocumentSignerSelectSchema.optional(),
  include: DocumentSignerIncludeSchema.optional(),
  data: z.union([ DocumentSignerCreateInputSchema,DocumentSignerUncheckedCreateInputSchema ]),
}).strict() ;

export const DocumentSignerUpsertArgsSchema: z.ZodType<Prisma.DocumentSignerUpsertArgs> = z.object({
  select: DocumentSignerSelectSchema.optional(),
  include: DocumentSignerIncludeSchema.optional(),
  where: DocumentSignerWhereUniqueInputSchema,
  create: z.union([ DocumentSignerCreateInputSchema,DocumentSignerUncheckedCreateInputSchema ]),
  update: z.union([ DocumentSignerUpdateInputSchema,DocumentSignerUncheckedUpdateInputSchema ]),
}).strict() ;

export const DocumentSignerCreateManyArgsSchema: z.ZodType<Prisma.DocumentSignerCreateManyArgs> = z.object({
  data: z.union([ DocumentSignerCreateManyInputSchema,DocumentSignerCreateManyInputSchema.array() ]),
  skipDuplicates: z.boolean().optional(),
}).strict() ;

export const DocumentSignerCreateManyAndReturnArgsSchema: z.ZodType<Prisma.DocumentSignerCreateManyAndReturnArgs> = z.object({
  data: z.union([ DocumentSignerCreateManyInputSchema,DocumentSignerCreateManyInputSchema.array() ]),
  skipDuplicates: z.boolean().optional(),
}).strict() ;

export const DocumentSignerDeleteArgsSchema: z.ZodType<Prisma.DocumentSignerDeleteArgs> = z.object({
  select: DocumentSignerSelectSchema.optional(),
  include: DocumentSignerIncludeSchema.optional(),
  where: DocumentSignerWhereUniqueInputSchema,
}).strict() ;

export const DocumentSignerUpdateArgsSchema: z.ZodType<Prisma.DocumentSignerUpdateArgs> = z.object({
  select: DocumentSignerSelectSchema.optional(),
  include: DocumentSignerIncludeSchema.optional(),
  data: z.union([ DocumentSignerUpdateInputSchema,DocumentSignerUncheckedUpdateInputSchema ]),
  where: DocumentSignerWhereUniqueInputSchema,
}).strict() ;

export const DocumentSignerUpdateManyArgsSchema: z.ZodType<Prisma.DocumentSignerUpdateManyArgs> = z.object({
  data: z.union([ DocumentSignerUpdateManyMutationInputSchema,DocumentSignerUncheckedUpdateManyInputSchema ]),
  where: DocumentSignerWhereInputSchema.optional(),
}).strict() ;

export const updateManyDocumentSignerCreateManyAndReturnArgsSchema: z.ZodType<Prisma.updateManyDocumentSignerCreateManyAndReturnArgs> = z.object({
  data: z.union([ DocumentSignerUpdateManyMutationInputSchema,DocumentSignerUncheckedUpdateManyInputSchema ]),
  where: DocumentSignerWhereInputSchema.optional(),
}).strict() ;

export const DocumentSignerDeleteManyArgsSchema: z.ZodType<Prisma.DocumentSignerDeleteManyArgs> = z.object({
  where: DocumentSignerWhereInputSchema.optional(),
}).strict() ;

export const SignatureFieldCreateArgsSchema: z.ZodType<Prisma.SignatureFieldCreateArgs> = z.object({
  select: SignatureFieldSelectSchema.optional(),
  include: SignatureFieldIncludeSchema.optional(),
  data: z.union([ SignatureFieldCreateInputSchema,SignatureFieldUncheckedCreateInputSchema ]),
}).strict() ;

export const SignatureFieldUpsertArgsSchema: z.ZodType<Prisma.SignatureFieldUpsertArgs> = z.object({
  select: SignatureFieldSelectSchema.optional(),
  include: SignatureFieldIncludeSchema.optional(),
  where: SignatureFieldWhereUniqueInputSchema,
  create: z.union([ SignatureFieldCreateInputSchema,SignatureFieldUncheckedCreateInputSchema ]),
  update: z.union([ SignatureFieldUpdateInputSchema,SignatureFieldUncheckedUpdateInputSchema ]),
}).strict() ;

export const SignatureFieldCreateManyArgsSchema: z.ZodType<Prisma.SignatureFieldCreateManyArgs> = z.object({
  data: z.union([ SignatureFieldCreateManyInputSchema,SignatureFieldCreateManyInputSchema.array() ]),
  skipDuplicates: z.boolean().optional(),
}).strict() ;

export const SignatureFieldCreateManyAndReturnArgsSchema: z.ZodType<Prisma.SignatureFieldCreateManyAndReturnArgs> = z.object({
  data: z.union([ SignatureFieldCreateManyInputSchema,SignatureFieldCreateManyInputSchema.array() ]),
  skipDuplicates: z.boolean().optional(),
}).strict() ;

export const SignatureFieldDeleteArgsSchema: z.ZodType<Prisma.SignatureFieldDeleteArgs> = z.object({
  select: SignatureFieldSelectSchema.optional(),
  include: SignatureFieldIncludeSchema.optional(),
  where: SignatureFieldWhereUniqueInputSchema,
}).strict() ;

export const SignatureFieldUpdateArgsSchema: z.ZodType<Prisma.SignatureFieldUpdateArgs> = z.object({
  select: SignatureFieldSelectSchema.optional(),
  include: SignatureFieldIncludeSchema.optional(),
  data: z.union([ SignatureFieldUpdateInputSchema,SignatureFieldUncheckedUpdateInputSchema ]),
  where: SignatureFieldWhereUniqueInputSchema,
}).strict() ;

export const SignatureFieldUpdateManyArgsSchema: z.ZodType<Prisma.SignatureFieldUpdateManyArgs> = z.object({
  data: z.union([ SignatureFieldUpdateManyMutationInputSchema,SignatureFieldUncheckedUpdateManyInputSchema ]),
  where: SignatureFieldWhereInputSchema.optional(),
}).strict() ;

export const updateManySignatureFieldCreateManyAndReturnArgsSchema: z.ZodType<Prisma.updateManySignatureFieldCreateManyAndReturnArgs> = z.object({
  data: z.union([ SignatureFieldUpdateManyMutationInputSchema,SignatureFieldUncheckedUpdateManyInputSchema ]),
  where: SignatureFieldWhereInputSchema.optional(),
}).strict() ;

export const SignatureFieldDeleteManyArgsSchema: z.ZodType<Prisma.SignatureFieldDeleteManyArgs> = z.object({
  where: SignatureFieldWhereInputSchema.optional(),
}).strict() ;

export const SignatureCreateArgsSchema: z.ZodType<Prisma.SignatureCreateArgs> = z.object({
  select: SignatureSelectSchema.optional(),
  include: SignatureIncludeSchema.optional(),
  data: z.union([ SignatureCreateInputSchema,SignatureUncheckedCreateInputSchema ]),
}).strict() ;

export const SignatureUpsertArgsSchema: z.ZodType<Prisma.SignatureUpsertArgs> = z.object({
  select: SignatureSelectSchema.optional(),
  include: SignatureIncludeSchema.optional(),
  where: SignatureWhereUniqueInputSchema,
  create: z.union([ SignatureCreateInputSchema,SignatureUncheckedCreateInputSchema ]),
  update: z.union([ SignatureUpdateInputSchema,SignatureUncheckedUpdateInputSchema ]),
}).strict() ;

export const SignatureCreateManyArgsSchema: z.ZodType<Prisma.SignatureCreateManyArgs> = z.object({
  data: z.union([ SignatureCreateManyInputSchema,SignatureCreateManyInputSchema.array() ]),
  skipDuplicates: z.boolean().optional(),
}).strict() ;

export const SignatureCreateManyAndReturnArgsSchema: z.ZodType<Prisma.SignatureCreateManyAndReturnArgs> = z.object({
  data: z.union([ SignatureCreateManyInputSchema,SignatureCreateManyInputSchema.array() ]),
  skipDuplicates: z.boolean().optional(),
}).strict() ;

export const SignatureDeleteArgsSchema: z.ZodType<Prisma.SignatureDeleteArgs> = z.object({
  select: SignatureSelectSchema.optional(),
  include: SignatureIncludeSchema.optional(),
  where: SignatureWhereUniqueInputSchema,
}).strict() ;

export const SignatureUpdateArgsSchema: z.ZodType<Prisma.SignatureUpdateArgs> = z.object({
  select: SignatureSelectSchema.optional(),
  include: SignatureIncludeSchema.optional(),
  data: z.union([ SignatureUpdateInputSchema,SignatureUncheckedUpdateInputSchema ]),
  where: SignatureWhereUniqueInputSchema,
}).strict() ;

export const SignatureUpdateManyArgsSchema: z.ZodType<Prisma.SignatureUpdateManyArgs> = z.object({
  data: z.union([ SignatureUpdateManyMutationInputSchema,SignatureUncheckedUpdateManyInputSchema ]),
  where: SignatureWhereInputSchema.optional(),
}).strict() ;

export const updateManySignatureCreateManyAndReturnArgsSchema: z.ZodType<Prisma.updateManySignatureCreateManyAndReturnArgs> = z.object({
  data: z.union([ SignatureUpdateManyMutationInputSchema,SignatureUncheckedUpdateManyInputSchema ]),
  where: SignatureWhereInputSchema.optional(),
}).strict() ;

export const SignatureDeleteManyArgsSchema: z.ZodType<Prisma.SignatureDeleteManyArgs> = z.object({
  where: SignatureWhereInputSchema.optional(),
}).strict() ;

export const CertificateCreateArgsSchema: z.ZodType<Prisma.CertificateCreateArgs> = z.object({
  select: CertificateSelectSchema.optional(),
  include: CertificateIncludeSchema.optional(),
  data: z.union([ CertificateCreateInputSchema,CertificateUncheckedCreateInputSchema ]),
}).strict() ;

export const CertificateUpsertArgsSchema: z.ZodType<Prisma.CertificateUpsertArgs> = z.object({
  select: CertificateSelectSchema.optional(),
  include: CertificateIncludeSchema.optional(),
  where: CertificateWhereUniqueInputSchema,
  create: z.union([ CertificateCreateInputSchema,CertificateUncheckedCreateInputSchema ]),
  update: z.union([ CertificateUpdateInputSchema,CertificateUncheckedUpdateInputSchema ]),
}).strict() ;

export const CertificateCreateManyArgsSchema: z.ZodType<Prisma.CertificateCreateManyArgs> = z.object({
  data: z.union([ CertificateCreateManyInputSchema,CertificateCreateManyInputSchema.array() ]),
  skipDuplicates: z.boolean().optional(),
}).strict() ;

export const CertificateCreateManyAndReturnArgsSchema: z.ZodType<Prisma.CertificateCreateManyAndReturnArgs> = z.object({
  data: z.union([ CertificateCreateManyInputSchema,CertificateCreateManyInputSchema.array() ]),
  skipDuplicates: z.boolean().optional(),
}).strict() ;

export const CertificateDeleteArgsSchema: z.ZodType<Prisma.CertificateDeleteArgs> = z.object({
  select: CertificateSelectSchema.optional(),
  include: CertificateIncludeSchema.optional(),
  where: CertificateWhereUniqueInputSchema,
}).strict() ;

export const CertificateUpdateArgsSchema: z.ZodType<Prisma.CertificateUpdateArgs> = z.object({
  select: CertificateSelectSchema.optional(),
  include: CertificateIncludeSchema.optional(),
  data: z.union([ CertificateUpdateInputSchema,CertificateUncheckedUpdateInputSchema ]),
  where: CertificateWhereUniqueInputSchema,
}).strict() ;

export const CertificateUpdateManyArgsSchema: z.ZodType<Prisma.CertificateUpdateManyArgs> = z.object({
  data: z.union([ CertificateUpdateManyMutationInputSchema,CertificateUncheckedUpdateManyInputSchema ]),
  where: CertificateWhereInputSchema.optional(),
}).strict() ;

export const updateManyCertificateCreateManyAndReturnArgsSchema: z.ZodType<Prisma.updateManyCertificateCreateManyAndReturnArgs> = z.object({
  data: z.union([ CertificateUpdateManyMutationInputSchema,CertificateUncheckedUpdateManyInputSchema ]),
  where: CertificateWhereInputSchema.optional(),
}).strict() ;

export const CertificateDeleteManyArgsSchema: z.ZodType<Prisma.CertificateDeleteManyArgs> = z.object({
  where: CertificateWhereInputSchema.optional(),
}).strict() ;

export const SigningTemplateCreateArgsSchema: z.ZodType<Prisma.SigningTemplateCreateArgs> = z.object({
  select: SigningTemplateSelectSchema.optional(),
  include: SigningTemplateIncludeSchema.optional(),
  data: z.union([ SigningTemplateCreateInputSchema,SigningTemplateUncheckedCreateInputSchema ]),
}).strict() ;

export const SigningTemplateUpsertArgsSchema: z.ZodType<Prisma.SigningTemplateUpsertArgs> = z.object({
  select: SigningTemplateSelectSchema.optional(),
  include: SigningTemplateIncludeSchema.optional(),
  where: SigningTemplateWhereUniqueInputSchema,
  create: z.union([ SigningTemplateCreateInputSchema,SigningTemplateUncheckedCreateInputSchema ]),
  update: z.union([ SigningTemplateUpdateInputSchema,SigningTemplateUncheckedUpdateInputSchema ]),
}).strict() ;

export const SigningTemplateCreateManyArgsSchema: z.ZodType<Prisma.SigningTemplateCreateManyArgs> = z.object({
  data: z.union([ SigningTemplateCreateManyInputSchema,SigningTemplateCreateManyInputSchema.array() ]),
  skipDuplicates: z.boolean().optional(),
}).strict() ;

export const SigningTemplateCreateManyAndReturnArgsSchema: z.ZodType<Prisma.SigningTemplateCreateManyAndReturnArgs> = z.object({
  data: z.union([ SigningTemplateCreateManyInputSchema,SigningTemplateCreateManyInputSchema.array() ]),
  skipDuplicates: z.boolean().optional(),
}).strict() ;

export const SigningTemplateDeleteArgsSchema: z.ZodType<Prisma.SigningTemplateDeleteArgs> = z.object({
  select: SigningTemplateSelectSchema.optional(),
  include: SigningTemplateIncludeSchema.optional(),
  where: SigningTemplateWhereUniqueInputSchema,
}).strict() ;

export const SigningTemplateUpdateArgsSchema: z.ZodType<Prisma.SigningTemplateUpdateArgs> = z.object({
  select: SigningTemplateSelectSchema.optional(),
  include: SigningTemplateIncludeSchema.optional(),
  data: z.union([ SigningTemplateUpdateInputSchema,SigningTemplateUncheckedUpdateInputSchema ]),
  where: SigningTemplateWhereUniqueInputSchema,
}).strict() ;

export const SigningTemplateUpdateManyArgsSchema: z.ZodType<Prisma.SigningTemplateUpdateManyArgs> = z.object({
  data: z.union([ SigningTemplateUpdateManyMutationInputSchema,SigningTemplateUncheckedUpdateManyInputSchema ]),
  where: SigningTemplateWhereInputSchema.optional(),
}).strict() ;

export const updateManySigningTemplateCreateManyAndReturnArgsSchema: z.ZodType<Prisma.updateManySigningTemplateCreateManyAndReturnArgs> = z.object({
  data: z.union([ SigningTemplateUpdateManyMutationInputSchema,SigningTemplateUncheckedUpdateManyInputSchema ]),
  where: SigningTemplateWhereInputSchema.optional(),
}).strict() ;

export const SigningTemplateDeleteManyArgsSchema: z.ZodType<Prisma.SigningTemplateDeleteManyArgs> = z.object({
  where: SigningTemplateWhereInputSchema.optional(),
}).strict() ;

export const BlockchainWalletCreateArgsSchema: z.ZodType<Prisma.BlockchainWalletCreateArgs> = z.object({
  select: BlockchainWalletSelectSchema.optional(),
  include: BlockchainWalletIncludeSchema.optional(),
  data: z.union([ BlockchainWalletCreateInputSchema,BlockchainWalletUncheckedCreateInputSchema ]),
}).strict() ;

export const BlockchainWalletUpsertArgsSchema: z.ZodType<Prisma.BlockchainWalletUpsertArgs> = z.object({
  select: BlockchainWalletSelectSchema.optional(),
  include: BlockchainWalletIncludeSchema.optional(),
  where: BlockchainWalletWhereUniqueInputSchema,
  create: z.union([ BlockchainWalletCreateInputSchema,BlockchainWalletUncheckedCreateInputSchema ]),
  update: z.union([ BlockchainWalletUpdateInputSchema,BlockchainWalletUncheckedUpdateInputSchema ]),
}).strict() ;

export const BlockchainWalletCreateManyArgsSchema: z.ZodType<Prisma.BlockchainWalletCreateManyArgs> = z.object({
  data: z.union([ BlockchainWalletCreateManyInputSchema,BlockchainWalletCreateManyInputSchema.array() ]),
  skipDuplicates: z.boolean().optional(),
}).strict() ;

export const BlockchainWalletCreateManyAndReturnArgsSchema: z.ZodType<Prisma.BlockchainWalletCreateManyAndReturnArgs> = z.object({
  data: z.union([ BlockchainWalletCreateManyInputSchema,BlockchainWalletCreateManyInputSchema.array() ]),
  skipDuplicates: z.boolean().optional(),
}).strict() ;

export const BlockchainWalletDeleteArgsSchema: z.ZodType<Prisma.BlockchainWalletDeleteArgs> = z.object({
  select: BlockchainWalletSelectSchema.optional(),
  include: BlockchainWalletIncludeSchema.optional(),
  where: BlockchainWalletWhereUniqueInputSchema,
}).strict() ;

export const BlockchainWalletUpdateArgsSchema: z.ZodType<Prisma.BlockchainWalletUpdateArgs> = z.object({
  select: BlockchainWalletSelectSchema.optional(),
  include: BlockchainWalletIncludeSchema.optional(),
  data: z.union([ BlockchainWalletUpdateInputSchema,BlockchainWalletUncheckedUpdateInputSchema ]),
  where: BlockchainWalletWhereUniqueInputSchema,
}).strict() ;

export const BlockchainWalletUpdateManyArgsSchema: z.ZodType<Prisma.BlockchainWalletUpdateManyArgs> = z.object({
  data: z.union([ BlockchainWalletUpdateManyMutationInputSchema,BlockchainWalletUncheckedUpdateManyInputSchema ]),
  where: BlockchainWalletWhereInputSchema.optional(),
}).strict() ;

export const updateManyBlockchainWalletCreateManyAndReturnArgsSchema: z.ZodType<Prisma.updateManyBlockchainWalletCreateManyAndReturnArgs> = z.object({
  data: z.union([ BlockchainWalletUpdateManyMutationInputSchema,BlockchainWalletUncheckedUpdateManyInputSchema ]),
  where: BlockchainWalletWhereInputSchema.optional(),
}).strict() ;

export const BlockchainWalletDeleteManyArgsSchema: z.ZodType<Prisma.BlockchainWalletDeleteManyArgs> = z.object({
  where: BlockchainWalletWhereInputSchema.optional(),
}).strict() ;

export const ApiKeyCreateArgsSchema: z.ZodType<Prisma.ApiKeyCreateArgs> = z.object({
  select: ApiKeySelectSchema.optional(),
  include: ApiKeyIncludeSchema.optional(),
  data: z.union([ ApiKeyCreateInputSchema,ApiKeyUncheckedCreateInputSchema ]),
}).strict() ;

export const ApiKeyUpsertArgsSchema: z.ZodType<Prisma.ApiKeyUpsertArgs> = z.object({
  select: ApiKeySelectSchema.optional(),
  include: ApiKeyIncludeSchema.optional(),
  where: ApiKeyWhereUniqueInputSchema,
  create: z.union([ ApiKeyCreateInputSchema,ApiKeyUncheckedCreateInputSchema ]),
  update: z.union([ ApiKeyUpdateInputSchema,ApiKeyUncheckedUpdateInputSchema ]),
}).strict() ;

export const ApiKeyCreateManyArgsSchema: z.ZodType<Prisma.ApiKeyCreateManyArgs> = z.object({
  data: z.union([ ApiKeyCreateManyInputSchema,ApiKeyCreateManyInputSchema.array() ]),
  skipDuplicates: z.boolean().optional(),
}).strict() ;

export const ApiKeyCreateManyAndReturnArgsSchema: z.ZodType<Prisma.ApiKeyCreateManyAndReturnArgs> = z.object({
  data: z.union([ ApiKeyCreateManyInputSchema,ApiKeyCreateManyInputSchema.array() ]),
  skipDuplicates: z.boolean().optional(),
}).strict() ;

export const ApiKeyDeleteArgsSchema: z.ZodType<Prisma.ApiKeyDeleteArgs> = z.object({
  select: ApiKeySelectSchema.optional(),
  include: ApiKeyIncludeSchema.optional(),
  where: ApiKeyWhereUniqueInputSchema,
}).strict() ;

export const ApiKeyUpdateArgsSchema: z.ZodType<Prisma.ApiKeyUpdateArgs> = z.object({
  select: ApiKeySelectSchema.optional(),
  include: ApiKeyIncludeSchema.optional(),
  data: z.union([ ApiKeyUpdateInputSchema,ApiKeyUncheckedUpdateInputSchema ]),
  where: ApiKeyWhereUniqueInputSchema,
}).strict() ;

export const ApiKeyUpdateManyArgsSchema: z.ZodType<Prisma.ApiKeyUpdateManyArgs> = z.object({
  data: z.union([ ApiKeyUpdateManyMutationInputSchema,ApiKeyUncheckedUpdateManyInputSchema ]),
  where: ApiKeyWhereInputSchema.optional(),
}).strict() ;

export const updateManyApiKeyCreateManyAndReturnArgsSchema: z.ZodType<Prisma.updateManyApiKeyCreateManyAndReturnArgs> = z.object({
  data: z.union([ ApiKeyUpdateManyMutationInputSchema,ApiKeyUncheckedUpdateManyInputSchema ]),
  where: ApiKeyWhereInputSchema.optional(),
}).strict() ;

export const ApiKeyDeleteManyArgsSchema: z.ZodType<Prisma.ApiKeyDeleteManyArgs> = z.object({
  where: ApiKeyWhereInputSchema.optional(),
}).strict() ;

export const AuditLogCreateArgsSchema: z.ZodType<Prisma.AuditLogCreateArgs> = z.object({
  select: AuditLogSelectSchema.optional(),
  include: AuditLogIncludeSchema.optional(),
  data: z.union([ AuditLogCreateInputSchema,AuditLogUncheckedCreateInputSchema ]),
}).strict() ;

export const AuditLogUpsertArgsSchema: z.ZodType<Prisma.AuditLogUpsertArgs> = z.object({
  select: AuditLogSelectSchema.optional(),
  include: AuditLogIncludeSchema.optional(),
  where: AuditLogWhereUniqueInputSchema,
  create: z.union([ AuditLogCreateInputSchema,AuditLogUncheckedCreateInputSchema ]),
  update: z.union([ AuditLogUpdateInputSchema,AuditLogUncheckedUpdateInputSchema ]),
}).strict() ;

export const AuditLogCreateManyArgsSchema: z.ZodType<Prisma.AuditLogCreateManyArgs> = z.object({
  data: z.union([ AuditLogCreateManyInputSchema,AuditLogCreateManyInputSchema.array() ]),
  skipDuplicates: z.boolean().optional(),
}).strict() ;

export const AuditLogCreateManyAndReturnArgsSchema: z.ZodType<Prisma.AuditLogCreateManyAndReturnArgs> = z.object({
  data: z.union([ AuditLogCreateManyInputSchema,AuditLogCreateManyInputSchema.array() ]),
  skipDuplicates: z.boolean().optional(),
}).strict() ;

export const AuditLogDeleteArgsSchema: z.ZodType<Prisma.AuditLogDeleteArgs> = z.object({
  select: AuditLogSelectSchema.optional(),
  include: AuditLogIncludeSchema.optional(),
  where: AuditLogWhereUniqueInputSchema,
}).strict() ;

export const AuditLogUpdateArgsSchema: z.ZodType<Prisma.AuditLogUpdateArgs> = z.object({
  select: AuditLogSelectSchema.optional(),
  include: AuditLogIncludeSchema.optional(),
  data: z.union([ AuditLogUpdateInputSchema,AuditLogUncheckedUpdateInputSchema ]),
  where: AuditLogWhereUniqueInputSchema,
}).strict() ;

export const AuditLogUpdateManyArgsSchema: z.ZodType<Prisma.AuditLogUpdateManyArgs> = z.object({
  data: z.union([ AuditLogUpdateManyMutationInputSchema,AuditLogUncheckedUpdateManyInputSchema ]),
  where: AuditLogWhereInputSchema.optional(),
}).strict() ;

export const updateManyAuditLogCreateManyAndReturnArgsSchema: z.ZodType<Prisma.updateManyAuditLogCreateManyAndReturnArgs> = z.object({
  data: z.union([ AuditLogUpdateManyMutationInputSchema,AuditLogUncheckedUpdateManyInputSchema ]),
  where: AuditLogWhereInputSchema.optional(),
}).strict() ;

export const AuditLogDeleteManyArgsSchema: z.ZodType<Prisma.AuditLogDeleteManyArgs> = z.object({
  where: AuditLogWhereInputSchema.optional(),
}).strict() ;