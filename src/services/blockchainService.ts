// src/services/blockchainService.ts
import { ethers, ContractTransaction, BigNumberish } from 'ethers';
import { config } from '../config';
import { EventEmitter } from 'events';
import { CONTRACT_ABI } from '@/constants/contract-abi';



interface DocumentInfo {
  initialDigest: string;
  finalHash: string;
  isLocked: boolean;
}

export class BlockchainService extends EventEmitter {
  private contract: ethers.Contract;
  private provider: ethers.Provider;
  private signer: ethers.Signer;

  constructor() {
    super();
    this.provider = new ethers.JsonRpcProvider(config.blockchain.rpcUrl);
    this.signer = new ethers.Wallet(config.blockchain.privateKey, this.provider);
    this.contract = new ethers.Contract(
      config.blockchain.contractAddress,
      CONTRACT_ABI,
      this.signer
    );

    this.setupEventListeners();
  }

  private setupEventListeners() {
    this.contract.on('NewDocument', (docID: number, initialDigest: string, size: number) => {
      this.emit('documentCreated', {
        docID: docID.toString(),
        initialDigest,
        size: size
      });
    });

    this.contract.on('DocumentSigned', (docID: number, size: number, signedDigest: string) => {
      this.emit('documentSigned', {
        docID: docID.toString(),
        size: size,
        signedDigest
      });
    });

    this.contract.on('DocumentLocked', (docID: BigNumberish) => {
      this.emit('documentLocked', {
        docID: docID.toString()
      });
    });
  }

  private async waitForTransaction(tx: ContractTransaction): Promise<void> {
    try {
      const receipt = await this.provider.waitForTransaction(tx.data, config.blockchain.confirmations);
      if (receipt === null || receipt.status === 0) {
        throw new Error('Transaction failed');
      }
    } catch (error) {
      console.error('Transaction failed:', error);
      throw new Error('Blockchain transaction failed');
    }
  }

  async createDocument(initialDigest: string, signers: number): Promise<string> {
    try {
      // Generate unique docID using timestamp and random number
      const timestamp = Date.now();
      const random = Math.floor(Math.random() * 1000000);
      const docID = BigInt(timestamp) * BigInt(1000000) + BigInt(random);

      const gasPrice = await this.provider.getFeeData();
      const tx = await this.contract.newDocument(
        initialDigest,
        docID,
        signers,
        {
          gasPrice: gasPrice.gasPrice, // Add 20% to current gas price
          gasLimit: config.blockchain.gasLimit
        }
      );

      await this.waitForTransaction(tx);
      return docID.toString();
    } catch (error) {
      console.error('Document creation failed:', error);
      throw new Error('Failed to create document on blockchain');
    }
  }

  async signDocument(
    docId: string,
    signedDigest: string,
    currentSigners: number,
    isLastSigner: boolean
  ): Promise<void> {
    try {
      const gasPrice = (await this.provider.getFeeData()).gasPrice;
      const tx = await this.contract.signDocument(
        docId,
        signedDigest,
        currentSigners + 1,
        isLastSigner,
        {
          gasPrice: gasPrice ? ethers.toBigInt(gasPrice) : ethers.parseUnits('20', 'gwei'),
          gasLimit: config.blockchain.gasLimit
        }
      );

      await this.waitForTransaction(tx);
    } catch (error) {
      console.error('Document signing failed:', error);
      throw new Error('Failed to sign document on blockchain');
    }
  }

  async verifyDocument(docHash: string): Promise<boolean> {
    try {
      return await this.contract.verifyDocument(docHash);
    } catch (error) {
      console.error('Document verification failed:', error);
      throw new Error('Failed to verify document on blockchain');
    }
  }

  async getDocumentInfo(docHash: string): Promise<{
    initialDigest: string;
    signers: number[];
    signedDigests: string[];
  }> {
    try {
      const [initialDigest, size, signedDigests] = 
        await this.contract.getDocumentInfoByHash(docHash);
      
      return {
        initialDigest,
        signers: Array.from({ length: size.toNumber() }, (_, i) => i),
        signedDigests
      };
    } catch (error) {
      console.error('Failed to get document info:', error);
      throw new Error('Failed to retrieve document information');
    }
  }

  async getNumberOfSigners(docId: string): Promise<number> {
    try {
      const signers = await this.contract.getNumberOfSigners(docId);
      return signers.toNumber();
    } catch (error) {
      console.error('Failed to get number of signers:', error);
      throw new Error('Failed to retrieve signer count');
    }
  }

  async getDocumentByID(docId: string): Promise<DocumentInfo> {
    try {
      const doc = await this.contract.documents(docId);
      return {
        initialDigest: doc.initialDigest,
        finalHash: doc.finalHash,
        isLocked: doc.isLocked
      };
    } catch (error) {
      console.error('Failed to get document:', error);
      throw new Error('Failed to retrieve document');
    }
  }
}


// Example usage in document service
