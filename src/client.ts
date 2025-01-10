import axios, { AxiosInstance } from 'axios';
import { Config } from './config';
// import { Config } from './types';

export class DocumentClient {
  private client: AxiosInstance;

  constructor(config: Config) {
    this.client = axios.create({
      baseURL: config.baseUrl,
      timeout: config.timeout,
      headers: {
        'Authorization': `Bearer ${config.apiKey}`,
        'Content-Type': 'application/json'
      }
    });
  }

  async post(path: string, data: any) {
    const response = await this.client.post(path, data);
    return response.data;
  }

  async get(path: string) {
    const response = await this.client.get(path);
    return response.data;
  }

  // ... other HTTP methods
}
