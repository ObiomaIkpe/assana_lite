import { Module } from '@nestjs/common';
import { UsersService } from './users.service';
import { UsersController } from './users.controller';
import { TypeOrmModule } from '@nestjs/typeorm';
import { UserProfileService } from './user-profile.service';
import { User } from './Entity/user.entity';
import { UserProfile } from './Entity/user-profile.entity';
import { CloudinaryModule } from 'src/cloudinary/cloudinary.module';

@Module({
  imports: [TypeOrmModule.forFeature([User, UserProfile]), CloudinaryModule],
  providers: [UsersService, UserProfileService],
  controllers: [UsersController],
  exports: [UsersService, UserProfileService]
})
export class UsersModule {}
