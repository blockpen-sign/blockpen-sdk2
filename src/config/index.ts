// export const config = {
//     azure: {
//         storageConnectionString: process.env.AZURE_STORAGE_CONNECTION_STRING,
//         containerName: process.env.AZURE_CONTAINER_NAME,
//         communicationServiceConnectionString: process.env.AZURE_COMMUNICATION_SERVICE_CONNECTION_STRING
//       },
//       email: {
//         senderAddress: process.env.EMAIL_SENDER_ADDRESS
//       },
//       jwt: {
//         secret: process.env.JWT_SECRET,
//         expiresIn: '24h'
//       },
//       grpc: {
//         host: process.env.GRPC_HOST || 'localhost',
//         port: process.env.GRPC_PORT || '50051'
//       },
//     blockchain: {
//       rpcUrl: process.env.BLOCKCHAIN_RPC_URL || 'http://localhost:8545',
//       contractAddress: process.env.CONTRACT_ADDRESS,
//       privateKey: process.env.BLOCKCHAIN_PRIVATE_KEY,
//       gasLimit: process.env.GAS_LIMIT || '3000000',
//       confirmations: parseInt(process.env.CONFIRMATIONS || '1')
//     }
//   };

import { loadEnvConfig } from "@/utils";

interface PdfConfig {
  service: {
    host: string;
    port: number;
    timeout: number;
  };
  signature: {
    defaultSize: {
      width: number;
      height: number;
    };
    fontPath: string;
    timestampFormat: string;
  };
  validation: {
    timeout: number;
    maxRetries: number;
  };
}

interface SignServiceConfig {
  host: string;
  port: number;
  timeout: number;
  retries: number;
}

interface StorageConfig {
  azure: {
    connectionString: string;
    containerName: string;
    tempPath: string;
  };
}

export interface Config {
  env: string;
  pdf: PdfConfig;
  signService: SignServiceConfig;
  storage: StorageConfig;
  blockchain: {
    rpcUrl: string;
    contractAddress: string;
    privateKey: string;
    gasLimit: string;
    confirmations: number;
  };
}

// Load and validate environment variables
const env = loadEnvConfig();

export const config: Config = {
  env: env.NODE_ENV || 'development',
  
  pdf: {
    service: {
      host: env.PDF_SERVICE_HOST || 'localhost',
      port: parseInt(env.PDF_SERVICE_PORT || '50051'),
      timeout: parseInt(env.PDF_SERVICE_TIMEOUT || '30000')
    },
    signature: {
      defaultSize: {
        width: parseInt(env.SIGNATURE_WIDTH || '100'),
        height: parseInt(env.SIGNATURE_HEIGHT || '50')
      },
      fontPath: env.SIGNATURE_FONT_PATH || './assets/fonts/NotoSans-Light.ttf',
      timestampFormat: env.TIMESTAMP_FORMAT || 'YYYY-MM-DD HH:mm:ss'
    },
    validation: {
      timeout: parseInt(env.VALIDATION_TIMEOUT || '30000'),
      maxRetries: parseInt(env.VALIDATION_MAX_RETRIES || '3')
    }
  },

  signService: {
    host: env.SIGN_SERVICE_HOST || 'localhost',
    port: parseInt(env.SIGN_SERVICE_PORT || '50052'),
    timeout: parseInt(env.SIGN_SERVICE_TIMEOUT || '30000'),
    retries: parseInt(env.SIGN_SERVICE_RETRIES || '3')
  },

  storage: {
    azure: {
      connectionString: env.AZURE_STORAGE_CONNECTION_STRING || '',
      containerName: env.AZURE_CONTAINER_NAME || 'documents',
      tempPath: env.TEMP_PATH || './temp'
    }
  },

  blockchain: {
    rpcUrl: env.BLOCKCHAIN_RPC_URL || 'http://localhost:8545',
    contractAddress: env.CONTRACT_ADDRESS || '',
    privateKey: env.BLOCKCHAIN_PRIVATE_KEY || '',
    gasLimit: env.GAS_LIMIT || '3000000',
    confirmations: parseInt(env.CONFIRMATIONS || '1')
  }
};
