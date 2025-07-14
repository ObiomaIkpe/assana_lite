import {
  BadRequestException,
  UseInterceptors,
  UploadedFile,
} from '@nestjs/common';
import { FileInterceptor } from '@nestjs/platform-express';
import { diskStorage } from 'multer';
import { extname } from 'path';

const IMAGE_MIME_TYPES = ['image/jpeg', 'image/png', 'image/webp'];

export const multerImageOptions = {
  limits: {
    fileSize: 5 * 1024 * 1024, // 5 MB
  },
  fileFilter: (
    req: any,
    file: Express.Multer.File,
    cb: (error: Error | null, acceptFile: boolean) => void,
  ) => {
    if (!IMAGE_MIME_TYPES.includes(file.mimetype)) {
      return cb(
        new BadRequestException(
          'Only JPEG, PNG, and WEBP image files are allowed!',
        ),
        false,
      );
    }
    cb(null, true);
  },
};
