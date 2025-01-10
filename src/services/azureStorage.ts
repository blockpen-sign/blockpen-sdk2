import { BlobServiceClient } from '@azure/storage-blob';
import { config } from '../config';

export class AzureStorageService {
  private blobServiceClient: BlobServiceClient;
  private containerName: string;

  constructor() {
    if (!config.azure || !config.azure.storageConnectionString) {
      throw new Error('Azure storage connection string is not defined');
    }
    this.blobServiceClient = BlobServiceClient.fromConnectionString(
      config.azure.storageConnectionString
    );
    if (!config.azure.containerName) {
      throw new Error('Azure container name is not defined');
    }
    this.containerName = config.azure.containerName;
  }

  async uploadDocument(file: Buffer, fileName: string): Promise<string> {
    const containerClient = this.blobServiceClient.getContainerClient(
      this.containerName
    );
    const blockBlobClient = containerClient.getBlockBlobClient(fileName);
    
    await blockBlobClient.upload(file, file.length);
    return blockBlobClient.url;
  }

  async getDocument(fileName: string): Promise<Buffer> {
    const containerClient = this.blobServiceClient.getContainerClient(
      this.containerName
    );
    const blockBlobClient = containerClient.getBlockBlobClient(fileName);
    
    const downloadResponse = await blockBlobClient.download(0);
    const chunks = [];
    
    if (!downloadResponse.readableStreamBody) {
      throw new Error('Readable stream body is undefined');
    }
    for await (const chunk of downloadResponse.readableStreamBody) {
      chunks.push(Buffer.from(chunk));
    }
    
    return Buffer.concat(chunks);
  }
}