import { ConflictException, Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { UsersService } from 'src/users/users.service';
import { RegisterDto } from './DTOs/register.dto';
import * as bcrypt from 'bcryptjs';
import { LoginDto } from './DTOs/login.dto';
import { ConfigService } from '@nestjs/config';
import { Response } from 'express';

@Injectable()
export class AuthService {
    constructor(
    private readonly usersService: UsersService,
    private readonly jwtService: JwtService,
    private readonly configService: ConfigService
    ) {}

    async register(registerDto: RegisterDto) {
        const existingUser = await this.usersService.findByEmail(registerDto.email);
        if (existingUser) {
            throw new ConflictException('User already exists');
        }

        const hashedPassword = await bcrypt.hash(registerDto.password, 10);

        const user = await this.usersService.create({
            email: registerDto.email,
            password: hashedPassword
            });
        return {
            id: user.id,
            email: user.email,
        }
    }

    async login(loginDto: LoginDto, res: Response) {
        const user = await this.usersService.findByEmail(loginDto.email);
        if (!user || !(await bcrypt.compare(loginDto.password, user.password))) {
            throw new UnauthorizedException('Invalid credentials');
    }
    const {accessToken, refreshToken} = this.generateToken(user);

    res.cookie('refresh_token', refreshToken, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    path: '/auth/refresh',
    maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
  });
    return {accessToken, user}
}



    private generateToken(user: any) {
        const payload = { id: user.id, email: user.email, role: user.role };

        const accessToken = this.jwtService.sign(payload, {
            secret: this.configService.get<string>('JWT_ACCESS_SECRET'),
    expiresIn: '15m',
  });

  const refreshToken = this.jwtService.sign(payload, {
    expiresIn: '7d',
    secret: this.configService.get<string>('JWT_REFRESH_SECRET'),
  });

  return { accessToken, refreshToken };        
    }


    async refreshToken(res: Response, refreshToken: string) {
        if (!refreshToken) {
    throw new UnauthorizedException('Refresh token not found');
  }

  try {
    const payload = this.jwtService.verify(refreshToken, {
      secret: this.configService.get<string>('JWT_REFRESH_SECRET'),
    });

    const user = await this.usersService.findByEmail(payload.email);
    if (!user) {
      throw new UnauthorizedException('User not found');
    }

    const { accessToken, refreshToken: newRefreshToken } = this.generateToken(user);

    res.cookie('refresh_token', newRefreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      path: '/auth/refresh',
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    return { accessToken };
  } catch (err) {
    throw new UnauthorizedException('Invalid refresh token');
  }
    }
}
