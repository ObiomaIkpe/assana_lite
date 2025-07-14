import { Injectable, NotFoundException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Task } from './Entity/task.entity';
import { Repository } from 'typeorm';
import { Project } from 'src/projects/projectsEntity/project.entity';
import { UserProfile } from 'src/users/Entity/user-profile.entity';
import { CreateTaskDto } from './taskDto/create-task.dto';

@Injectable()
export class TasksService {
    constructor(
        @InjectRepository(Task) private taskRepo: Repository<Task>,
        @InjectRepository(Project) private projectRepo: Repository<Project>,
        @InjectRepository(UserProfile) private userProfileRepo: Repository<UserProfile>         
    ) {}

    async createTask(taskDto: CreateTaskDto, currentUserProfile: UserProfile): Promise<Task> {

        const {title, description, status, projectId, assignedToUserId} = taskDto

        const project = await this.projectRepo.findOne({
            where: {id: projectId},
            relations: ['owner', 'members']
        })
        if (!project) {
            throw new NotFoundException('Project not found');
        }

        const isCreatorPartOfProject = project.owner.id === currentUserProfile.id || project.members.some(member => member.id === currentUserProfile.id);

        let assignedTo: UserProfile | null = null;

        if(assignedToUserId) {
            assignedTo = await this.userProfileRepo.findOne({
                where: {id: assignedToUserId}   
        })
    }

        if (!assignedTo) {
        throw new NotFoundException('Assigned user not found');
        }

        const alreadyMember = project.members.some(m => m.id === assignedTo.id);
        if (!alreadyMember && assignedTo.id !== project.owner.id) {
        project.members.push(assignedTo); // auto-add assignee to project
        await this.projectRepo.save(project);
        }

        const task = this.taskRepo.create({
                title, description, status,project, assignedTo,
                createdBy: currentUserProfile,
            });

            return this.taskRepo.save(task);
    }
}
