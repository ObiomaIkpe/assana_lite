import {
  Body,
  Controller,
  Post,
  Req,
  UseGuards,
} from '@nestjs/common';
import { TasksService } from './tasks.service';
import { JwtAuthGuard } from 'src/auth/guards/jwt.auth-gaurd';
import { CreateTaskDto } from './taskDto/create-task.dto';
import { Task } from './Entity/task.entity';
import { RequestWithUserProfile } from '../common/interfaces/request-with-user-profile.interface';
import {
  ApiBearerAuth,
  ApiTags,
  ApiOperation,
  ApiResponse,
  ApiBody,
} from '@nestjs/swagger';

@ApiTags('Tasks') // Group this controller under "Tasks" in Swagger
@ApiBearerAuth() // Indicates that this route uses Bearer Auth (JWT)
@Controller('tasks')
@UseGuards(JwtAuthGuard)
export class TasksController {
  constructor(private readonly tasksService: TasksService) {}

  @Post()
  @ApiOperation({ summary: 'Create a new task under a project' })
  @ApiResponse({ status: 201, description: 'Task created successfully', type: Task })
  @ApiResponse({ status: 404, description: 'Project or Assigned user not found' })
  @ApiBody({ type: CreateTaskDto })
  async createTask(
    @Body() dto: CreateTaskDto,
    @Req() req: RequestWithUserProfile,
  ): Promise<Task> {
    if (!req.user?.profile) {
      throw new Error('User profile not found in request');
    }
    return this.tasksService.createTask(dto, req.user.profile);
  }
}
