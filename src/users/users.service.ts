import { Injectable, NotFoundException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { User } from './Entity/user.entity';
import { Repository } from 'typeorm';
import { UserProfile } from './Entity/user-profile.entity';
import { UpdateUserProfileDto } from './userProfile.dto.ts/update-user-profile.dto';

@Injectable()
export class UsersService {
    constructor(
        @InjectRepository(User) private  userRepo: Repository<User>,

        @InjectRepository(UserProfile) private  profileRepo: Repository<UserProfile>,
    ) {}

    async create(userData: Partial<User>): Promise<User> {
        const user = this.userRepo.create(userData);
        return this.userRepo.save(user);
    }

    async findByEmail(email: string): Promise<User | null> {
        return this.userRepo.findOne({ where: { email } });
    }
  
    async updateProfile(userId: number, dto: UpdateUserProfileDto): Promise<User> {
      //1. get the user
    const user = await this.userRepo.findOne({
      where: { id: userId },
      relations: ['profile'],
    });

    if (!user) {
      throw new NotFoundException('User not found');
    }

    // 2. Check if the user already has a profile
      let profile = user.profile;
       
      if (profile) {
      // Update existing profile
      profile = this.profileRepo.merge(profile, dto);
    } else {
      // Create a new profile and assign it
      profile = this.profileRepo.create(dto);
    }

      // 3. Assign profile to user
      user.profile = profile;

      // 4. Save user (because of cascade, profile gets saved too)
      return this.userRepo.save(user);
  }
}
