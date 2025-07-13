import { Column, Entity, JoinColumn, OneToOne, PrimaryGeneratedColumn } from "typeorm";
import { UserProfile } from "./user-profile.entity";
import { Role } from "src/auth/roles/roles.enum";

@Entity()
export class User {
  @PrimaryGeneratedColumn()
  id: number;

  @Column({ unique: true })
  email: string;

  @Column()
  password: string;

  @Column({ type: 'enum', enum: Role, default: Role.USER })
  role: Role;

  @OneToOne(() => UserProfile, profile => profile.user, { cascade: true, eager: true, nullable: true})
  @JoinColumn()
  profile: UserProfile | null;
}