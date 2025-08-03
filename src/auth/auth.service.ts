// src/auth/auth.service.ts
import { 
  Injectable, 
  ConflictException, 
  UnauthorizedException, 
  NotFoundException,
  BadRequestException,
  Logger 
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import * as bcrypt from 'bcryptjs';
import { randomBytes } from 'crypto';

import { Auth } from './entities/auth.entity';
import { UserProfile } from '../user-profile/entities/user-profile.entity';
import { EmailService } from './services/email.service';
import { 
  RegisterDto, 
  LoginDto, 
  
} from './dtos';
import { JwtPayload, AuthResponse, JwtTokens } from './interfaces/auth.interface';

@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name);

  constructor(
    @InjectRepository(Auth)
    private authRepository: Repository<Auth>,
    @InjectRepository(UserProfile)
    private userProfileRepository: Repository<UserProfile>,
    private jwtService: JwtService,
    private configService: ConfigService,
    private emailService: EmailService,
  ) {}

  async register(registerDto: RegisterDto): Promise<AuthResponse> {
    const { email, password, firstName, lastName, jobTitle, department } = registerDto;

    // Check if user already exists
    const existingAuth = await this.authRepository.findOne({ where: { email } });
    if (existingAuth) {
      throw new ConflictException('User with this email already exists');
    }

    // Hash password
    const saltRounds = 12;
    const passwordHash = await bcrypt.hash(password, saltRounds);

    // Generate email verification token
    const emailVerificationToken = this.generateSecureToken();

    // Create auth record
    const auth = this.authRepository.create({
      email,
      passwordHash,
      emailVerificationToken,
      emailVerified: false,
      isActive: true,
    });

    const savedAuth = await this.authRepository.save(auth);

    // Create user profile
    const userProfile = this.userProfileRepository.create({
      authId: savedAuth.id,
      firstName,
      lastName,
      jobTitle,
      department,
    });

    const savedProfile = await this.userProfileRepository.save(userProfile);

    // Send verification email
    try {
      const verificationUrl = `${this.configService.get('app.url')}/api/v1/auth/verify-email?token=${emailVerificationToken}`;
      await this.emailService.sendVerificationEmail(email, {
        firstName,
        verificationUrl,
      });
    } catch (error) {
      this.logger.error('Failed to send verification email:', error);
      // Don't fail registration if email fails
    }

    // Generate tokens (but user will need to verify email for full access)
    const tokens = await this.generateTokens({
      sub: savedAuth.id,
      email: savedAuth.email,
      profileId: savedProfile.id,
    });

    this.logger.log(`New user registered: ${email}`);

    return {
      user: {
        id: savedAuth.id,
        email: savedAuth.email,
        firstName: savedProfile.firstName,
        lastName: savedProfile.lastName,
        fullName: savedProfile.fullName,
        avatarUrl: savedProfile.avatarUrl,
        emailVerified: savedAuth.emailVerified,
      },
      tokens,
    };
  }

  async login(loginDto: LoginDto): Promise<AuthResponse> {
    const { email, password } = loginDto;

    const auth = await this.validateUser(email, password);
    if (!auth) {
      throw new UnauthorizedException('Invalid credentials');
    }

    // Update last login
    await this.authRepository.update(auth.id, { 
      lastLogin: new Date() 
    });

    // Get user profile