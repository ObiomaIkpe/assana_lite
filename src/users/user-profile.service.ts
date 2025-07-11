import { Injectable, NotFoundException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { UserProfile } from './Entity/user-profile.entity';
import { User } from './Entity/user.entity';

@Injectable()
export class UserProfileService {
  constructor(
    @InjectRepository(UserProfile)
    private readonly profileRepo: Repository<UserProfile>,
  ) {}

  async create(profileData: Partial<UserProfile>, user: User): Promise<UserProfile> {
    const profile = this.profileRepo.create({ ...profileData, user });
    return this.profileRepo.save(profile);
  }

  async update(userId: number, updates: Partial<UserProfile>): Promise<UserProfile> {
    const profile = await this.profileRepo.findOne({
      where: { user: { id: userId } },
    });
    if (!profile) throw new NotFoundException('Profile not found');
    Object.assign(profile, updates);
    return this.profileRepo.save(profile);
  }

  async findByUserId(userId: number): Promise<UserProfile> {
    const profile = await this.profileRepo.findOne({
      where: { user: { id: userId } },
    });
    if (!profile) throw new NotFoundException('Profile not found');
    return profile;
  }
}