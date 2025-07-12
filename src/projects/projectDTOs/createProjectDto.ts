export class CreateProjectDto {
  name: string;
  description?: string;
  isShared?: boolean;
  memberProfileIds?: string[];
}
