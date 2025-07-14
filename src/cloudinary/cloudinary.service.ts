// src/cloudinary/cloudinary.service.ts
import { Injectable } from '@nestjs/common';
import { v2 as cloudinary, UploadApiOptions } from 'cloudinary';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class CloudinaryService {
  constructor(private configService: ConfigService) {
    cloudinary.config({
      cloud_name: this.configService.get<string>('CLOUDINARY_CLOUD_NAME'),
      api_key: this.configService.get<string>('CLOUDINARY_API_KEY'),
      api_secret: this.configService.get<string>('CLOUDINARY_API_SECRET'),
    });
  }

  async uploadImage(buffer: Buffer, publicId?: string): Promise<string> {
    const uploadOptions: UploadApiOptions = {
      folder: 'user-avatars',
      public_id: publicId,
      overwrite: true,
      resource_type: 'image',
    };

    return new Promise((resolve, reject) => {
      cloudinary.uploader.upload_stream(uploadOptions, (error, result) => {
        if (error || !result) {
          return reject(error || new Error('Upload failed: No result returned'));
        }
        resolve(result.secure_url);
      }).end(buffer);
    });
  }
}
