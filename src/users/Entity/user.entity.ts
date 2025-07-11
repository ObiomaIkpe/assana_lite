import { Column, Entity, JoinColumn, OneToOne, PrimaryGeneratedColumn } from "typeorm";
import { UserProfile } from "./user-profile.entity";

@Entity()
export class User {
  @PrimaryGeneratedColumn()
  id: number;

  @Column({ unique: true })
  email: string;

  @Column()
  password: string;

  @Column({ default: 'user' })
  role: 'admin' | 'manager' | 'user';

  @OneToOne(() => UserProfile, profile => profile.user, { cascade: true, eager: true, nullable: true})
  @JoinColumn()
  profile?: UserProfile;
}