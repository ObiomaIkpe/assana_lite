import { Module } from '@nestjs/common';
import { ProjectsController } from './projects.controller';
import { ProjectsService } from './projects.service';
import { TypeOrmModule } from '@nestjs/typeorm';
import { Project } from './projectsEntity/project.entity';
import { User } from 'src/users/Entity/user.entity';
import { UserProfile } from 'src/users/Entity/user-profile.entity';

@Module({
  imports: [
    TypeOrmModule.forFeature([
      Project, User, UserProfile
    ])
  ],
  controllers: [ProjectsController],
  providers: [ProjectsService]
})
export class ProjectsModule {}
