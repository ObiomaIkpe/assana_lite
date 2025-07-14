import { Module } from '@nestjs/common';
import { TasksService } from './tasks.service';
import { TasksController } from './tasks.controller';
import { TypeOrmModule } from '@nestjs/typeorm';
import { Project } from 'src/projects/projectsEntity/project.entity';
import { UserProfile } from 'src/users/Entity/user-profile.entity';
import { Task } from './Entity/task.entity';

@Module({
  imports: [TypeOrmModule.forFeature([Task, Project, UserProfile])],
  providers: [TasksService],
  controllers: [TasksController]
})
export class TasksModule {}
