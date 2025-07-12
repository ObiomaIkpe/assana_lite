// src/seeder/seeder.module.ts
import { Module } from '@nestjs/common';
import { SeederService } from './user.seeder-service';
import { UsersModule } from 'src/users/users.module';

@Module({
  imports: [UsersModule],
  providers: [SeederService],
  exports: [SeederService],
})
export class SeederModule {}
