import { Injectable } from '@nestjs/common';
import { UsersService } from '../users/users.service';
import * as bcrypt from 'bcryptjs';
import { Role } from '../auth/roles/roles.enum';

@Injectable()
export class SeederService {
  constructor(private readonly usersService: UsersService) {}

  async seedUsers() {
    const users = [
      { email: 'admin@example.com', password: 'admin123', role: Role.ADMIN },
      { email: 'manager@example.com', password: 'manager123', role: Role.MANAGER },
      { email: 'user@example.com', password: 'user123', role: Role.USER },
    ];

    for (const user of users) {
      const exists = await this.usersService.findByEmail(user.email);
      if (!exists) {
        const hashed = await bcrypt.hash(user.password, 10);
        await this.usersService.create({ ...user, password: hashed });
        console.log(`✅ Created: ${user.email}`);
      } else {
        console.log(`⚠️ Already exists: ${user.email}`);
      }
    }
  }
}