import { Module } from '@nestjs/common';
import { TasksService } from './tasks.service';
import { TasksController } from './tasks.controller';
import { TasksService } from './tasks.service';

@Module({
  providers: [TasksService],
  controllers: [TasksController]
})
export class TasksModule {}
