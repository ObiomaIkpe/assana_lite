import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  ManyToOne,
  ManyToMany,
  JoinTable,
  CreateDateColumn,
  UpdateDateColumn,
  OneToMany,
} from 'typeorm';
import { UserProfile } from '../../users/Entity/user-profile.entity';
import { Task } from 'src/tasks/Entity/task.entity';

export enum ProjectStatus {
  PLANNING = 'PLANNING',
  IN_PROGRESS = 'IN_PROGRESS',
  COMPLETED = 'COMPLETED',
  ON_HOLD = 'ON_HOLD',
}

@Entity()
export class Project {
  @PrimaryGeneratedColumn()
  id: number;

  @Column()
  title: string;

  @Column({ nullable: true })
  description: string;

  @Column({
    type: 'enum',
    enum: ProjectStatus,
    default: ProjectStatus.PLANNING,
  })
  status: ProjectStatus;

  @CreateDateColumn()
  createdAt: Date;

  @UpdateDateColumn()
  updatedAt: Date;

  @ManyToOne(() => UserProfile, (userProfile) => userProfile.ownedProjects, {
    eager: true,
    nullable: false,
  })
  owner: UserProfile;

  @ManyToMany(() => UserProfile, (userProfile) => userProfile.sharedProjects, {
    cascade: true,
    eager: true,
  })
  @JoinTable()
  members: UserProfile[];

  @OneToMany(() => Task, (task) => task.project)
  tasks: Task[];
}
