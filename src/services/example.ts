import { BlockchainService } from './blockchainService';
import { CONTRACT_ABI } from '@/constants/contract-abi';
import { DocumentStatus, prisma } from '@/lib/pisma';
import { BlockchainEvent } from '@/types/blockchain';

export class DocumentService {
  private blockchainService: BlockchainService;

  constructor() {
    this.blockchainService = new BlockchainService();
    
    // Set up blockchain event handlers
    this.blockchainService.on('documentCreated', this.handleDocumentCreated.bind(this));
    this.blockchainService.on('documentSigned', this.handleDocumentSigned.bind(this));
    this.blockchainService.on('documentLocked', this.handleDocumentLocked.bind(this));
  }

  private async handleDocumentCreated(event: BlockchainEvent['DocumentCreated']) {
    await prisma.document.update({
      where: { id: event.docID },
      data: {
        status: 'PENDING',
        metadata: {
          initialDigest: event.initialDigest,
          expectedSigners: event.size
        }
      }
    });
  }

  private async handleDocumentSigned(event: BlockchainEvent['DocumentSigned']) {
    await prisma.document.update({
      where: { id: event.docID },
      data: {
        metadata: {
          currentSigners: event.size,
          lastSignedDigest: event.signedDigest
        }
      }
    });
  }

  private async handleDocumentLocked(event: BlockchainEvent['DocumentLocked']) {
    const doc = await this.blockchainService.getDocumentByID(event.docID);
    await prisma.document.update({
      where: { id: event.docID },
      data: {
        status: DocumentStatus.COMPLETED,
        metadata: {
          finalHash: doc.finalHash,
          isLocked: true
        }
      }
    });
  }
}