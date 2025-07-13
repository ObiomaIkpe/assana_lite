import { Body, Controller, Post, Req, UseGuards } from '@nestjs/common';
import { ApiBearerAuth, ApiOperation, ApiResponse, ApiTags } from '@nestjs/swagger';
import { JwtAuthGuard } from 'src/auth/guards/jwt.auth-gaurd';
import { CreateProjectDto } from './projectDTOs/createProjectDto';
import { Project } from './projectsEntity/project.entity';
import { ProjectsService } from './projects.service';
import { RequestWithUser } from 'src/common/interfaces/request-with-user.interface';

@ApiTags('projects')
@Controller('projects')
export class ProjectsController {
    constructor(
        private readonly projectsService: ProjectsService,
    ) {}

    @Post('create')
    @UseGuards(JwtAuthGuard)
    @ApiBearerAuth('access-token')
    @ApiOperation({ summary: 'Create a new project' })
    @ApiResponse({ status: 201, description: 'Project created successfully.' })
    @ApiResponse({ status: 403, description: 'Forbidden.' })
    async createProject(@Body() createProjectDto: CreateProjectDto,
    @Req() req: RequestWithUser): Promise<Project> {
        // Logic to create a project
        const user = req.user; 
        return this.projectsService.createProject(createProjectDto, user);
    }

}
