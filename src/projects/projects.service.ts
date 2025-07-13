import { Injectable, NotFoundException, ForbiddenException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Project } from './projectsEntity/project.entity';
import { Repository, In } from 'typeorm';
import { CreateProjectDto } from './projectDTOs/createProjectDto';
import { UpdateProjectDto } from './projectDTOs/update-project.dto';
import { User } from '../users/Entity/user.entity';
import { UserProfile } from '../users/Entity/user-profile.entity';

@Injectable()
export class ProjectsService {
  constructor(
    @InjectRepository(Project)
    private readonly projectRepo: Repository<Project>,

    @InjectRepository(UserProfile)
    private readonly profileRepo: Repository<UserProfile>,
    
    @InjectRepository(User)
    private readonly User: Repository<User>,
  ) {}

  async createProject(dto: CreateProjectDto, user: User): Promise<Project> {
  const ownerProfile = await this.profileRepo.findOne({
    where: { user: { id: user.id } },
  });

  if (!ownerProfile) {
    throw new NotFoundException('Owner profile not found.');
  }

  const members: UserProfile[] = dto.memberIds?.length
    ? await this.profileRepo.findBy({ id: In(dto.memberIds) })
    : [];

  const project = this.projectRepo.create({
    title: dto.title,
    description: dto.description,
    owner: ownerProfile,
    members,
  });

  return this.projectRepo.save(project);
}
  
}
