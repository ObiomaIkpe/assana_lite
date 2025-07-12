import { Body, Controller, Post, Req, Res } from '@nestjs/common';
import { ApiOperation, ApiResponse, ApiTags } from '@nestjs/swagger';
import { AuthService } from './auth.service';
import { RegisterDto } from './DTOs/register.dto';
import { LoginDto } from './DTOs/login.dto';
import { Request, Response } from 'express';

@ApiTags('auth')
@Controller('auth')
export class AuthController {
    constructor(private readonly authService: AuthService) {}

    @Post('register')
    @ApiOperation({ summary: 'Register a new user' })
    @ApiResponse({status: 201, description: 'User registered successfully'})
    register(@Body() registerDto: RegisterDto) { 
        return this.authService.register(registerDto);
    }

    @Post('login')
    @ApiOperation({ summary: 'Login a user' })
      @ApiResponse({ status: 200, description: 'User logged in' })
    login(@Body() loginDto: LoginDto, @Res({ passthrough: true }) res: Response) {
        return this.authService.login(loginDto, res);  
    } 

    @Post('refresh')
  @ApiOperation({ summary: 'Refresh access token using refresh token cookie' })
  async refresh(@Req() req: Request, @Res() res: Response) {
    const refreshToken = req.cookies?.['refresh_token'];
    const result = await this.authService.refreshToken(res, refreshToken);
    return res.json(result);
  }

  

}
