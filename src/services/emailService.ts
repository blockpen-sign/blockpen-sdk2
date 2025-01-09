import { EmailClient } from '@azure/communication-email';
import { config } from '../config';

export class EmailService {
  private client: EmailClient;

  constructor() {
    if (!config.azure.communicationServiceConnectionString) {
      throw new Error('Azure Communication Service connection string is not defined');
    }
    this.client = new EmailClient(config.azure.communicationServiceConnectionString);
  }

 async sendSignatureRequest(
    to: string,
    documentName: string,
    signingLink: string
  ): Promise<void> {
    try {
        
      await this.client.beginSend({
        senderAddress: config.email.senderAddress ||"",
        content: {
          subject: `Signature Required: ${documentName}`,
          plainText: `Please sign the document: ${signingLink}`,
          html: `
            <h2>Document Signature Required</h2>
            <p>You have been requested to sign the document: ${documentName}</p>
            <p><a href="${signingLink}">Click here to sign</a></p>
          `
        },
        recipients: {
          to: [{ address: to }]
        }
      });
    } catch (error) {
      if (error instanceof Error) {
        throw new Error(`Failed to send email: ${error.message}`);
      } else {
        throw new Error('Failed to send email: Unknown error');
      }
    }
  }

  async sendSignatureComplete(
    to: string,
    documentName: string,
    downloadLink: string
  ): Promise<void> {
    await this.client.beginSend({
      senderAddress: config.email.senderAddress || "",
      content: {
        subject: `Document Signed: ${documentName}`,
        plainText: `The document has been signed: ${downloadLink}`,
        html: `
          <h2>Document Signed Successfully</h2>
          <p>The document ${documentName} has been signed by all parties.</p>
          <p><a href="${downloadLink}">Download Document</a></p>
        `
      },
      recipients: {
        to: [{ address: to }]
      }
    });
  }
}