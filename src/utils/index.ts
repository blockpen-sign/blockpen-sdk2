interface EnvConfig {
  NODE_ENV?: string;
  PDF_SERVICE_HOST?: string;
  PDF_SERVICE_PORT?: string;
  PDF_SERVICE_TIMEOUT?: string;
  SIGNATURE_WIDTH?: string;
  SIGNATURE_HEIGHT?: string;
  SIGNATURE_FONT_PATH?: string;
  TIMESTAMP_FORMAT?: string;
  VALIDATION_TIMEOUT?: string;
  VALIDATION_MAX_RETRIES?: string;
  SIGN_SERVICE_HOST?: string;
  SIGN_SERVICE_PORT?: string;
  SIGN_SERVICE_TIMEOUT?: string;
  SIGN_SERVICE_RETRIES?: string;
  AZURE_STORAGE_CONNECTION_STRING?: string;
  AZURE_CONTAINER_NAME?: string;
  TEMP_PATH?: string;
  BLOCKCHAIN_RPC_URL?: string;
  CONTRACT_ADDRESS?: string;
  BLOCKCHAIN_PRIVATE_KEY?: string;
  GAS_LIMIT?: string;
  CONFIRMATIONS?: string;
}

export function loadEnvConfig(): EnvConfig {
  // Load environment variables from .env file in development
  if (process.env.NODE_ENV !== 'production') {
    require('dotenv').config();
  }

  validateRequiredEnvVars();

  const config: EnvConfig = {
    NODE_ENV: process.env.NODE_ENV,
    PDF_SERVICE_HOST: process.env.PDF_SERVICE_HOST,
    PDF_SERVICE_PORT: process.env.PDF_SERVICE_PORT,
    PDF_SERVICE_TIMEOUT: process.env.PDF_SERVICE_TIMEOUT,
    SIGNATURE_WIDTH: process.env.SIGNATURE_WIDTH,
    SIGNATURE_HEIGHT: process.env.SIGNATURE_HEIGHT,
    SIGNATURE_FONT_PATH: process.env.SIGNATURE_FONT_PATH,
    TIMESTAMP_FORMAT: process.env.TIMESTAMP_FORMAT,
    VALIDATION_TIMEOUT: process.env.VALIDATION_TIMEOUT,
    VALIDATION_MAX_RETRIES: process.env.VALIDATION_MAX_RETRIES,
    SIGN_SERVICE_HOST: process.env.SIGN_SERVICE_HOST,
    SIGN_SERVICE_PORT: process.env.SIGN_SERVICE_PORT,
    SIGN_SERVICE_TIMEOUT: process.env.SIGN_SERVICE_TIMEOUT,
    SIGN_SERVICE_RETRIES: process.env.SIGN_SERVICE_RETRIES,
    AZURE_STORAGE_CONNECTION_STRING: process.env.AZURE_STORAGE_CONNECTION_STRING,
    AZURE_CONTAINER_NAME: process.env.AZURE_CONTAINER_NAME,
    TEMP_PATH: process.env.TEMP_PATH,
    BLOCKCHAIN_RPC_URL: process.env.BLOCKCHAIN_RPC_URL,
    CONTRACT_ADDRESS: process.env.CONTRACT_ADDRESS,
    BLOCKCHAIN_PRIVATE_KEY: process.env.BLOCKCHAIN_PRIVATE_KEY,
    GAS_LIMIT: process.env.GAS_LIMIT,
    CONFIRMATIONS: process.env.CONFIRMATIONS,
  };

  return config;
}

function validateRequiredEnvVars() {
  const required = [
    'AZURE_STORAGE_CONNECTION_STRING',
    'CONTRACT_ADDRESS',
    'BLOCKCHAIN_PRIVATE_KEY'
  ];

  const missing = required.filter(key => !process.env[key]);

  if (missing.length > 0) {
    throw new Error(`Missing required environment variables: ${missing.join(', ')}`);
  }
}
