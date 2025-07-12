import { Controller, Get, Req, UseGuards } from '@nestjs/common';
import { ApiBearerAuth, ApiOperation, ApiTags } from '@nestjs/swagger';
import { JwtAuthGuard } from 'src/auth/guards/jwt.auth-gaurd';

@ApiTags('users')
@Controller('users')
export class UsersController {
    @UseGuards(JwtAuthGuard)
    @ApiBearerAuth('access-token')
    @ApiOperation({ summary: 'Get current user information' })
    @Get('me')
    getMe(@Req() req) {
        return req.user;
    }
}


