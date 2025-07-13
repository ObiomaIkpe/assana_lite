import { ProjectStatus } from '../projectsEntity/project.entity';

export class ReturnProjectDto {
  id: number;
  title: string;
  description?: string;
  status: ProjectStatus;
  createdAt: Date;
  updatedAt: Date;
  owner: {
    id: number;
    firstName?: string;
    lastName?: string;
  };
  members: {
    id: number;
    firstName?: string;
    lastName?: string;
  }[];
}
