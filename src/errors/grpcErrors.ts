import { Status } from '@grpc/grpc-js/build/src/constants';

export class GrpcError extends Error {
  constructor(public code: Status, message: string) {
    super(message);
    this.name = 'GrpcError';
  }
}

export const handleGrpcError = (error: any) => {
  const code = error.code;
  let status = 500;
  let message = 'Internal server error';

  switch (code) {
    case Status.NOT_FOUND:
      status = 404;
      message = 'Resource not found';
      break;
    case Status.INVALID_ARGUMENT:
      status = 400;
      message = 'Invalid request parameters';
      break;
    case Status.PERMISSION_DENIED:
      status = 403;
      message = 'Permission denied';
      break;
    case Status.UNAUTHENTICATED:
      status = 401;
      message = 'Authentication required';
      break;
  }

  return { status, message };
};
