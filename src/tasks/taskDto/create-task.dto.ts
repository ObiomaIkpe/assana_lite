import { IsEnum, IsNotEmpty, IsOptional, IsString, IsNumber } from 'class-validator';
import { TaskStatus } from '../Entity/task.entity';
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';

export class CreateTaskDto {
  @ApiProperty({ example: 'Design login page', description: 'Title of the task' })
  @IsNotEmpty()
  @IsString()
  title: string;

  @ApiPropertyOptional({ example: 'Create a responsive login UI with validations', description: 'Detailed description of the task' })
  @IsOptional()
  @IsString()
  description?: string;

  @ApiPropertyOptional({ enum: TaskStatus, example: TaskStatus.TODO, description: 'Current status of the task' })
  @IsOptional()
  @IsEnum(TaskStatus)
  status?: TaskStatus;

  @ApiProperty({ example: 3, description: 'ID of the project to which this task belongs' })
  @IsNotEmpty()
  @IsNumber()
  projectId: number;

  @ApiPropertyOptional({ example: 7, description: 'ID of the user to assign the task to' })
  @IsOptional()
  @IsNumber()
  assignedToUserId?: number;
}
