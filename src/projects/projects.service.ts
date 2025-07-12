import { Injectable, NotFoundException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Project } from './projectsEntity/project.entity';
import { Repository } from 'typeorm';
import { User } from 'src/users/Entity/user.entity';
import { UserProfile } from 'src/users/Entity/user-profile.entity';
import { CreateProjectDto } from './projectDTOs/createProjectDto';

@Injectable()
export class ProjectsService {
    constructor(
        @InjectRepository(Project)
        private readonly projectRepository: Repository<Project>,

        @InjectRepository(User)
        private readonly userRepository: Repository<User>,

        @InjectRepository(UserProfile)
        private readonly userProfileRepository: Repository<UserProfile>
    ) {}

    async createProject(createProjectDto: CreateProjectDto, userId: number): Promise<Project> {
        const user = await this.userRepository.findOne({
            where: {id: userId},
            relations: ['profile']
        })
        if (!user || !user.profile){
            throw new NotFoundException('User not found');
        }

        const { name, description, isShared, memberProfileIds } = createProjectDto;

  const members = memberProfileIds?.length
    ? await this.userProfileRepository.findBy(memberProfileIds)
    : [];

  const project = this.projectRepository.create({
    name,
    description,
    isShared,
    owner: user.profile,
    members,
  });

  // ✅ THIS RETURN FIXES THE ERROR
  return await this.projectRepository.save(project);
    }
}

