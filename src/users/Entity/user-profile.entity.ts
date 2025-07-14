import { Column, Entity, OneToOne, PrimaryGeneratedColumn, OneToMany, ManyToMany } from 'typeorm';
import { User } from './user.entity';
import { Project } from '../../projects/projectsEntity/project.entity';
import { Exclude } from 'class-transformer';
import { Task } from 'src/tasks/Entity/task.entity';

@Entity()
export class UserProfile {
  @PrimaryGeneratedColumn()
  id: number;

  @Column({ nullable: true })
  firstName: string;

  @Column({ nullable: true })
  lastName: string;

  @Column({ nullable: true })
  avatarUrl: string;

  @OneToOne(() => User, user => user.profile)
  @Exclude()
  user: User;

  @OneToMany(() => Project, project => project.owner)
  ownedProjects: Project[];

  @ManyToMany(() => Project, project => project.members)
  sharedProjects: Project[];

  @OneToMany(() => Task, (task) => task.assignedTo)
  assignedTasks: Task[];

  @OneToMany(() => Task, (task) => task.createdBy)
  createdTasks: Task[];
}