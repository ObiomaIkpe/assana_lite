import { Body, Controller, Get, NotFoundException, Patch, Put, Req, Request, UploadedFile, UseGuards, UseInterceptors } from '@nestjs/common';
import { Express } from 'express';
import { ApiBearerAuth, ApiBody, ApiConsumes, ApiOperation, ApiResponse, ApiTags } from '@nestjs/swagger';
import { JwtAuthGuard } from 'src/auth/guards/jwt.auth-gaurd';
import { UsersService } from './users.service';
import { UpdateUserProfileDto } from './userProfile.dto.ts/update-user-profile.dto';
import { User } from './Entity/user.entity';
import { Repository } from 'typeorm';
import { UserProfile } from './Entity/user-profile.entity';
import { InjectRepository } from '@nestjs/typeorm';
import { CurrentUser } from 'src/auth/decorators/current-user.decorator';
import { CloudinaryService } from 'src/cloudinary/cloudinary.service';
import { FileInterceptor } from '@nestjs/platform-express';
import { multerImageOptions } from 'src/common/multer-options';

@ApiTags('users')
@Controller('users')
export class UsersController {
    constructor(
        private  usersService: UsersService,
    @InjectRepository(UserProfile)
    private readonly profileRepo: Repository<UserProfile>,
    @InjectRepository(User)
    private readonly userRepo: Repository<User>,
    private readonly cloudinaryService: CloudinaryService,
    ) {}

    @UseGuards(JwtAuthGuard)
    @ApiBearerAuth('access-token')
    @ApiOperation({ summary: 'Get current user information' })
    @Get('me')
    getMe(@Req() req) {
        return req.user;
    }


    //update user profile DTO.
    @Put('profile')
    @UseGuards(JwtAuthGuard)
    @ApiBearerAuth('access-token') 
    @ApiOperation({ summary: 'Update the current user profile' })
    @ApiConsumes('multipart/form-data')
    @UseInterceptors(FileInterceptor('avatar', multerImageOptions))
    @ApiBody({
    schema: {
        type: 'object',
        properties: {
        firstName: { type: 'string' },
        lastName: { type: 'string' },
        avatar: { type: 'string', format: 'binary' },
    },
  },
})
    @ApiResponse({ status: 200, description: 'User profile updated successfully', type: User })
    @ApiResponse({ status: 401, description: 'Unauthorized' })
    @ApiResponse({ status: 404, description: 'User not found' })

    async updateProfile(
    @CurrentUser() user: User,
    @UploadedFile() file: Express.MulterFile,
    @Body() profileData: UpdateUserProfileDto) {
    
    if (file) {
        const avatarUrl = await this.cloudinaryService.uploadImage(file.buffer, `user-${user.id}`);
        profileData.avatarUrl = avatarUrl;
    }
        return this.usersService.updateProfile(user.id, profileData);
        }
    }     



