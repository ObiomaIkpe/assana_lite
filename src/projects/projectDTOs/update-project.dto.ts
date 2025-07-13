import { PartialType } from '@nestjs/swagger';
import { CreateProjectDto } from './createProjectDto';

export class UpdateProjectDto extends PartialType(CreateProjectDto) {}