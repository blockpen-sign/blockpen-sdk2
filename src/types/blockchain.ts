export interface BlockchainEvent {
  DocumentCreated: {
    docID: string;
    initialDigest: string;
    size: number;
  };
  DocumentSigned: {
    docID: string;
    size: number;
    signedDigest: string;
  };
  DocumentLocked: {
    docID: string;
  };
}
