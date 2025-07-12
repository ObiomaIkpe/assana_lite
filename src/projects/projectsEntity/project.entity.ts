import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  ManyToOne,
  ManyToMany,
  JoinTable,
  CreateDateColumn,
  UpdateDateColumn,
} from 'typeorm';
import { UserProfile } from 'src/users/Entity/user-profile.entity';

@Entity()
export class Project {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column()
  name: string;

  @Column({ nullable: true })
  description?: string;

  @Column({ default: false })
  isShared: boolean;

  @ManyToOne(() => UserProfile, profile => profile.ownedProjects, { eager: true })
  owner: UserProfile;

  @ManyToMany(() => UserProfile, profile => profile.sharedProjects, { eager: true })
  @JoinTable()
  members: UserProfile[];

  @CreateDateColumn()
  createdAt: Date;

  @UpdateDateColumn()
  updatedAt: Date;
}