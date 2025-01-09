// src/services/pdfService.ts
import * as grpc from '@grpc/grpc-js';
import * as protoLoader from '@grpc/proto-loader';
import { config } from '../config';
import { AzureStorageService } from './azureStorage';
import { BlockchainService } from './blockchainService';

interface ImageStamp {
  img?: Buffer;
  x1: number;
  y1: number;
  x2: number;
  y2: number;
  page: number;
}

interface SignatureStatus {
  pubkeyFingerprint: string;
  intact: boolean;
  changed: boolean;
  commonName: string;
  email: string;
  certificate: string;
}

export class PDFService {
  private pdfClient: any;
  private storageService: AzureStorageService;
  private blockchainService: BlockchainService;

  constructor() {
    const packageDefinition = protoLoader.loadSync('./proto/pdf-service.proto', {
      keepCase: true,
      longs: String,
      enums: String,
      defaults: true,
      oneofs: true
    });

    const proto = grpc.loadPackageDefinition(packageDefinition);
    this.pdfClient = new (proto as any).BlockPenPdf(
      config.pdf.service,
      grpc.credentials.createInsecure()
    );

    this.storageService = new AzureStorageService();
    this.blockchainService = new BlockchainService();
  }

  async signDocument(
    companyId: number,
    documentId: string,
    pubkeyFingerprint: string,
    imageStamp?: ImageStamp
  ): Promise<Buffer> {
    try {
      // Get document from storage
      const documentBuffer = await this.storageService.getDocument(documentId);

      // Prepare image stamp if provided
      const defaultSize = config.pdf.signature.defaultSize;
    const stamp = imageStamp ? {
      img: imageStamp.img || Buffer.from([]),
      x1: imageStamp.x1,
      y1: imageStamp.y1,
      x2: imageStamp.x2 || imageStamp.x1 + defaultSize.width,
      y2: imageStamp.y2 || imageStamp.y1 + defaultSize.height,
      page: imageStamp.page
    } : undefined;

      // Sign document using PDF service
      const signResponse = await new Promise((resolve, reject) => {
        this.pdfClient.SignDoc({
          doc: documentBuffer,
          pubkey_fp: pubkeyFingerprint,
          image_stamp: stamp,
          companyid: companyId
        }, (error: any, response: any) => {
          if (error) reject(error);
          else resolve(response);
        });
      });

      // Get document hash for blockchain
      const signedDocHash = await this.calculateDocumentHash((signResponse as any).signed_doc);

      // Update blockchain
      await this.blockchainService.signDocument(
        documentId,
        signedDocHash,
        1, // Current signer number
        false // Is last signer
      );

      return Buffer.from((signResponse as any).signed_doc);
    } catch (error) {
      console.error('Document signing failed:', error);
      throw new Error('Failed to sign document');
    }
  }

  async verifyDocument(documentBuffer: Buffer): Promise<SignatureStatus[]> {
    try {
      const response: any = await new Promise((resolve, reject) => {
        this.pdfClient.Integrity({
          doc: documentBuffer
        }, (error: any, response: any) => {
          if (error) reject(error);
          else resolve(response);
        });
      });

      return response.signs.map((sign: any) => ({
        pubkeyFingerprint: sign.pubkey_fp,
        intact: sign.intact,
        changed: sign.changed,
        commonName: sign.cn,
        email: sign.email,
        certificate: sign.cert
      }));
    } catch (error) {
      console.error('Document verification failed:', error);
      throw new Error('Failed to verify document');
    }
  }

  public async calculateDocumentHash(buffer: Buffer): Promise<string> {
    const crypto = require('crypto');
    return crypto.createHash('sha256').update(buffer).digest('hex');
  }
}

// src/services/documentService.ts (Updated)
