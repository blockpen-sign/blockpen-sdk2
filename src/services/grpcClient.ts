import * as grpc from '@grpc/grpc-js';
import * as protoLoader from '@grpc/proto-loader';
import { config } from '../config';
import { CertificateRequest, SignRequest } from '@/types/common';

export class GrpcClient {
  private static instance: GrpcClient;
  private client: any;

  private constructor() {
    const packageDefinition = protoLoader.loadSync('./proto/sign-service.proto', {
      keepCase: true,
      longs: String,
      enums: String,
      defaults: true,
      oneofs: true
    });

    const proto = grpc.loadPackageDefinition(packageDefinition) as any;
    this.client = new proto.blockpensign.BlockPenSign(
      `${config.grpc.host}:${config.grpc.port}`,
      grpc.credentials.createInsecure()
    );
  }

  public static getInstance(): GrpcClient {
    if (!GrpcClient.instance) {
      GrpcClient.instance = new GrpcClient();
    }
    return GrpcClient.instance;
  }

  public async signData(request: SignRequest): Promise<Buffer> {
    return new Promise((resolve, reject) => {
      this.client.signData({
        companyid: request.companyId,
        cert: { data: request.certificateFingerprint },
        data: request.data,
        algo: request.algorithm
      }, (err: any, response: any) => {
        if (err) reject(err);
        else resolve(Buffer.from(response.data));
      });
    });
  }

  public async createCertificate(request: CertificateRequest): Promise<string> {
    return new Promise((resolve, reject) => {
      this.client.createCertificate({
        companyid: request.companyId,
        ca: { data: request.caFingerprint },
        opts: {
          comman_name: request.options.commonName,
          email: request.options.email,
          organization: request.options.organization,
          country: request.options.country,
          isCA: request.options.isCA
        }
      }, (err: any, response: any) => {
        if (err) reject(err);
        else resolve(response.data);
      });
    });
  }
}