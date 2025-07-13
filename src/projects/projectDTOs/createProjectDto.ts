import { IsNotEmpty, IsString, IsOptional, IsEnum, IsArray, IsInt } from 'class-validator';
import { ProjectStatus } from '../projectsEntity/project.entity';
import { ApiProperty } from '@nestjs/swagger';

export class CreateProjectDto {
  @ApiProperty()
  @IsString()
  @IsNotEmpty()
  title: string;

  @ApiProperty({ required: false })
  @IsString()
  @IsOptional()
  description?: string;

  @ApiProperty({ enum: ProjectStatus, default: ProjectStatus.PLANNING })
  @IsEnum(ProjectStatus)
  @IsOptional()
  status?: ProjectStatus;

  @ApiProperty({ type: [Number], required: false, description: 'UserProfile IDs of project members' })
  @IsArray()
  @IsInt({ each: true })
  @IsOptional()
  memberIds?: number[];
}
