// src/tasks/entities/task.entity.ts
import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  ManyToOne,
  CreateDateColumn,
  UpdateDateColumn,
} from 'typeorm';
import { Project } from '../../projects/projectsEntity/project.entity';
import { UserProfile } from '../../users/Entity/user-profile.entity';
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';

export enum TaskStatus {
  TODO = 'TODO',
  IN_PROGRESS = 'IN_PROGRESS',
  DONE = 'DONE',
}

@Entity()
export class Task {
  @ApiProperty({ example: 1 })
  @PrimaryGeneratedColumn()
  id: number;

  @ApiProperty({ example: 'Design onboarding screen' })
  @Column()
  title: string;

  @ApiPropertyOptional({ example: 'Create the UI/UX for the new user onboarding' })
  @Column({ nullable: true })
  description: string;

  @ApiProperty({ enum: TaskStatus, example: TaskStatus.TODO })
  @Column({
    type: 'enum',
    enum: TaskStatus,
    default: TaskStatus.TODO,
  })
  status: TaskStatus;

  @ApiProperty({ type: () => Project })
  @ManyToOne(() => Project, (project) => project.tasks, {
    onDelete: 'CASCADE',
  })
  project: Project;

  @ApiPropertyOptional({ type: () => UserProfile })
  @ManyToOne(() => UserProfile, { nullable: true })
  assignedTo: UserProfile;

  @ApiProperty({ type: () => UserProfile })
  @ManyToOne(() => UserProfile, { nullable: false })
  createdBy: UserProfile;

  @ApiProperty({ example: new Date().toISOString() })
  @CreateDateColumn()
  createdAt: Date;

  @ApiProperty({ example: new Date().toISOString() })
  @UpdateDateColumn()
  updatedAt: Date;
}
