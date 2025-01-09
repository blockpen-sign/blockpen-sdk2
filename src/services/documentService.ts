
// src/services/documentService.ts (Updated)
import { BlockchainService } from './blockchainService';

import { createHash } from 'crypto';
import { prisma } from '@/lib/pisma';
import { AzureStorageService } from './azureStorage';
import { PDFService } from './pdfService';

// export class DocumentService {
//   private blockchainService: BlockchainService;
//   private storageService: AzureStorageService;

//   constructor() {
//     this.blockchainService = new BlockchainService();
//     this.storageService = new AzureStorageService();
//   }

//   async createDocument(
//     companyId: number,
//     userId: string,
//     file: Buffer,
//     signers: string[]
//   ) {
//     // Upload file to Azure Storage
//     const fileUrl = await this.storageService.uploadDocument(
//       file,
//       `${companyId}/${Date.now()}`
//     );

//     // Calculate document hash
//     const initialDigest = this.calculateDocumentHash(file);

//     // Create document on blockchain
//     const docId = await this.blockchainService.createDocument(
//       initialDigest,
//       signers.length
//     );

//     // Store in database
//     const document = await prisma.document.create({
//       data: {
//         companyId,
//         userId,
//         status: 'PENDING',
//         fileUrl,
//         blockchainDocId: docId.toString(),
//         initialDigest,
//         metadata: {
//           signers,
//           currentSigners: 0
//         }
//       }
//     });

//     return document;
//   }

//   async signDocument(
//     documentId: string,
//     userId: string,
//     signature: Buffer,
//     coordinates: any
//   ) {
//     const document = await prisma.document.findUnique({
//       where: { id: documentId },
//       include: {
//         signatures: true
//       }
//     });

//     if (!document) {
//       throw new Error('Document not found');
//     }

//     const metadata = document.metadata as any;
//     const currentSigners = document.signatures.length;
//     const isLastSigner = currentSigners + 1 === metadata.signers.length;

//     // Calculate signature digest
//     const signedDigest = this.calculateSignatureHash(signature);

//     // Sign on blockchain
//     await this.blockchainService.signDocument(
//      document.blockchainDocId,
//       signedDigest,
//       currentSigners,
//       isLastSigner
//     );

//     // Store signature in database
//     const sig = await prisma.signature.create({
//       data: {
//         documentId,
//         userId,
//         signatureData: signature.toString('base64'),
//         coordinates,
//         status: 'COMPLETED'
//       }
//     });

//     // Update document status if all signatures collected
//     if (isLastSigner) {
//       await prisma.document.update({
//         where: { id: documentId },
//         data: {
//           status: 'SIGNED',
//           metadata: {
//             ...metadata,
//             finalDigest: signedDigest
//           }
//         }
//       });
//     }

//     return sig;
//   }

//   async verifyDocument(documentHash: string) {
//     try {
//       const isValid = await this.blockchainService.verifyDocument(documentHash);
//       if (!isValid) {
//         return {
//           valid: false,
//           message: 'Document not found or has been modified'
//         };
//       }

//       const documentInfo = await this.blockchainService.getDocumentInfo(
//         documentHash
//       );

//       return {
//         valid: true,
//         info: documentInfo
//       };
//     } catch (error) {
//       console.error('Document verification failed:', error);
//       throw new Error('Failed to verify document');
//     }
//   }

//   private calculateDocumentHash(file: Buffer): string {
//     return createHash('sha256').update(file).digest('hex');
//   }

//   private calculateSignatureHash(signature: Buffer): string {
//     return createHash('sha256').update(signature).digest('hex');
//   }
// }

// src/config/index.ts (Updated)

// prisma/schema.prisma (Updates)
// model Document {
//   // ... existing fields
//   blockchainDocId  String?
//   initialDigest    String?
//   metadata         Json?      // Includes signers, currentSigners, finalDigest
// }



export class DocumentService {
    private pdfService: PDFService;
    private blockchainService: BlockchainService;
    private storageService: AzureStorageService;
  
    constructor() {
      this.pdfService = new PDFService();
      this.blockchainService = new BlockchainService();
      this.storageService = new AzureStorageService();
    }
  
    async createDocument(
      companyId: number,
      userId: string,
      file: Buffer,
      signers: string[]
    ) {
      // Upload to Azure Storage
      const fileUrl = await this.storageService.uploadDocument(
        file,
        `${companyId}/${Date.now()}`
      );
  
      // Get document hash
      const documentHash = await this.pdfService.calculateDocumentHash(file);
  
      // Create document on blockchain
      const blockchainDocId = await this.blockchainService.createDocument(
        documentHash,
        signers.length
      );
  
      // Store in database
      const document = await prisma.document.create({
        data: {
          companyId,
          userId,
          status: 'PENDING',
          fileUrl,
          blockchainDocId,
          metadata: {
            signers,
            currentSigners: 0
          }
        }
      });
  
      return document;
    }
  
    async signDocument(
      documentId: string,
      userId: string,
      pubkeyFingerprint: string,
      coordinates?: {
        x: number;
        y: number;
        page: number;
      }
    ) {
      const document = await prisma.document.findUnique({
        where: { id: documentId },
        include: { signatures: true }
      });
  
      if (!document) {
        throw new Error('Document not found');
      }
  
      // Convert coordinates to image stamp format if provided
      const imageStamp = coordinates ? {
        x1: coordinates.x,
        y1: coordinates.y,
        x2: coordinates.x + 100, // Default signature width
        y2: coordinates.y + 50,  // Default signature height
        page: coordinates.page
      } : undefined;
  
      // Sign document using PDF service
      const signedDoc = await this.pdfService.signDocument(
        document.companyId,
        documentId,
        pubkeyFingerprint,
        imageStamp
      );
  
      // Upload signed document
      const signedFileUrl = await this.storageService.uploadDocument(
        signedDoc,
        `${document.companyId}/signed_${Date.now()}`
      );
  
      // Update document status
      await prisma.document.update({
        where: { id: documentId },
        data: {
          status: 'SIGNED',
          fileUrl: signedFileUrl
        }
      });
  
      return {
        documentId,
        signedFileUrl,
        status: 'SIGNED'
      };
    }
  
    async verifyDocument(documentId: string) {
      const document = await prisma.document.findUnique({
        where: { id: documentId }
      });
  
      if (!document) {
        throw new Error('Document not found');
      }
  
      const documentBuffer = await this.storageService.getDocument(document.fileUrl);
      const signatures = await this.pdfService.verifyDocument(documentBuffer);
  
      // Verify on blockchain
      const documentHash = await this.pdfService.calculateDocumentHash(documentBuffer);
      const blockchainVerification = await this.blockchainService.verifyDocument(documentHash);
  
      return {
        signatures,
        blockchainVerified: blockchainVerification,
        documentId,
        status: document.status
      };
    }
  }