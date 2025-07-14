import 'express';

declare global {
  namespace Express {
    interface MulterFile {
      fieldname: string;
      originalname: string;
      encoding: string;
      mimetype: string;
      size: number;
      buffer: Buffer;
    }

    // This fixes the error you're seeing
    interface Request {
      file?: MulterFile;
      files?: MulterFile[];
    }
  }
}
