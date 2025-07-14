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
    // 1. Get the user with profile relation
    const user = await this.userRepo.findOne({
      where: { id: userId },
      relations: ['profile', 'profile.user', 'profile.ownedProjects', 'profile.sharedProjects'],
    });

    console.log(user)

    if (!user) {
    throw new NotFoundException('User not found');
    }

    // 2. Update or create profile
    let profile = user.profile;

    if (profile) {
      profile = this.profileRepo.merge(profile, dto);
    } else {
      profile = this.profileRepo.create(dto);
      profile.user = user; 
    }

    // 3. Assign updated profile back to user
    user.profile = profile;

    // 4. Save user — cascade will handle profile
    return this.userRepo.save(user); 
}

  
}
