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

import { Auth } from './entity';
import { UserProfile } from '../user-profile/entities/user-profile.entity';
import { EmailService } from './services/email.service';
import { ChangePasswordDto } from './dtos/change-password.dto';
import { JwtPayload, AuthResponse, JwtTokens } from './interfaces/auth.interface';
import { RegisterDto } from './dtos/register.dto';
import { LoginDto } from './dtos/login.dto';
import { ForgotPasswordDto } from './dtos/forgot-password.dto';
import { ResetPasswordDto } from './dtos/reset-password.dto';

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
    const saltRounds = 8;
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
    const userProfile = await this.userProfileRepository.findOne({
      where: { authId: auth.id },
    });

    if (!userProfile) {
      throw new NotFoundException('User profile not found');
    }

    // Generate tokens
    const tokens = await this.generateTokens({
      sub: auth.id,
      email: auth.email,
      profileId: userProfile.id,
    });

    this.logger.log(`User logged in: ${email}`);

    return {
      user: {
        id: auth.id,
        email: auth.email,
        firstName: userProfile.firstName,
        lastName: userProfile.lastName,
        fullName: userProfile.fullName,
        avatarUrl: userProfile.avatarUrl,
        emailVerified: auth.emailVerified,
      },
      tokens,
    };
  }

  async validateUser(email: string, password: string): Promise<Auth | null> {
    const auth = await this.authRepository.findOne({ 
      where: { email, isActive: true } 
    });

    if (auth && await bcrypt.compare(password, auth.passwordHash)) {
      return auth;
    }

    return null;
  }

  async verifyEmail(token: string): Promise<{ message: string }> {
    const auth = await this.authRepository.findOne({
      where: { emailVerificationToken: token },
      relations: ['userProfile'],
    });

    if (!auth) {
      throw new BadRequestException('Invalid or expired verification token');
    }

    if (auth.emailVerified) {
      throw new BadRequestException('Email already verified');
    }

    // Update auth record
    await this.authRepository.update(auth.id, {
      emailVerified: true,
      emailVerificationToken: null,
    });

    // Send welcome email
    try {
      const loginUrl = `${this.configService.get('app.url')}/login`;
      await this.emailService.sendWelcomeEmail(auth.email, {
        firstName: auth.userProfile.firstName,
        loginUrl,
      });
    } catch (error) {
      this.logger.error('Failed to send welcome email:', error);
    }

    this.logger.log(`Email verified for user: ${auth.email}`);

    return { message: 'Email verified successfully' };
  }

  async forgotPassword(forgotPasswordDto: ForgotPasswordDto): Promise<{ message: string }> {
    const { email } = forgotPasswordDto;

    const auth = await this.authRepository.findOne({
      where: { email, isActive: true },
      relations: ['userProfile'],
    });

    if (!auth) {
      // Don't reveal if email exists or not
      return { message: 'If an account with that email exists, we sent a password reset link' };
    }

    // Generate reset token and expiry (1 hour)
    const resetToken = this.generateSecureToken();
    const resetExpiry = new Date();
    resetExpiry.setHours(resetExpiry.getHours() + 1);

    // Update auth record
    await this.authRepository.update(auth.id, {
      passwordResetToken: resetToken,
      passwordResetExpires: resetExpiry,
    });

    // Send reset email
    try {
      const resetUrl = `${this.configService.get('app.url')}/reset-password?token=${resetToken}`;
      await this.emailService.sendPasswordResetEmail(auth.email, {
        firstName: auth.userProfile.firstName,
        resetUrl,
      });
    } catch (error) {
      this.logger.error('Failed to send password reset email:', error);
      throw new BadRequestException('Failed to send password reset email');
    }

    this.logger.log(`Password reset requested for: ${email}`);

    return { message: 'If an account with that email exists, we sent a password reset link' };
  }

  async resetPassword(resetPasswordDto: ResetPasswordDto): Promise<{ message: string }> {
    const { token, newPassword } = resetPasswordDto;

    const auth = await this.authRepository.findOne({
      where: { 
        passwordResetToken: token,
        isActive: true,
      },
    });

    if (!auth || !auth.passwordResetExpires || auth.passwordResetExpires < new Date()) {
      throw new BadRequestException('Invalid or expired reset token');
    }

    // Hash new password
    const saltRounds = 12;
    const passwordHash = await bcrypt.hash(newPassword, saltRounds);

    // Update auth record
    await this.authRepository.update(auth.id, {
      passwordHash,
      passwordResetToken: null,
      passwordResetExpires: null,
    });

    this.logger.log(`Password reset completed for user: ${auth.email}`);

    return { message: 'Password reset successfully' };
  }

  async changePassword(
    authId: string, 
    changePasswordDto: ChangePasswordDto,
  ): Promise<{ message: string }> {
    const { currentPassword, newPassword } = changePasswordDto;

    const auth = await this.authRepository.findOne({ 
      where: { id: authId, isActive: true } 
    });

    if (!auth) {
      throw new NotFoundException('Auth record not found');
    }

    // Verify current password
    const isCurrentPasswordValid = await bcrypt.compare(currentPassword, auth.passwordHash);
    if (!isCurrentPasswordValid) {
      throw new UnauthorizedException('Current password is incorrect');
    }

    // Hash new password
    const saltRounds = 12;
    const passwordHash = await bcrypt.hash(newPassword, saltRounds);

    // Update password
    await this.authRepository.update(authId, { passwordHash });

    this.logger.log(`Password changed for user: ${auth.email}`);

    return { message: 'Password changed successfully' };
  }

  async refreshTokens(refreshToken: string): Promise<JwtTokens> {
    try {
      const payload = this.jwtService.verify(refreshToken, {
        secret: this.configService.get('jwt.refreshSecret'),
      });

      // Verify auth record still exists and is active
      const auth = await this.authRepository.findOne({
        where: { id: payload.sub, isActive: true },
      });

      if (!auth) {
        throw new UnauthorizedException('Invalid refresh token');
      }

      // Generate new tokens
      const tokens = await this.generateTokens({
        sub: payload.sub,
        email: payload.email,
        profileId: payload.profileId,
        organizationId: payload.organizationId,
      });

      return tokens;
    } catch (error) {
      throw new UnauthorizedException('Invalid refresh token');
    }
  }

  async logout(authId: string): Promise<{ message: string }> {
    // In a more sophisticated system, you might blacklist the JWT token
    // For now, we just log the logout event
    this.logger.log(`User logged out: ${authId}`);
    return { message: 'Logged out successfully' };
  }

  async resendVerificationEmail(email: string): Promise<{ message: string }> {
    const auth = await this.authRepository.findOne({
      where: { email, isActive: true },
      relations: ['userProfile'],
    });

    if (!auth) {
      // Don't reveal if email exists or not
      return { message: 'If an account with that email exists, we sent a verification email' };
    }

    if (auth.emailVerified) {
      throw new BadRequestException('Email is already verified');
    }

    // Generate new verification token
    const emailVerificationToken = this.generateSecureToken();
    await this.authRepository.update(auth.id, { emailVerificationToken });

    // Send verification email
    try {
      const verificationUrl = `${this.configService.get('app.url')}/api/v1/auth/verify-email?token=${emailVerificationToken}`;
      await this.emailService.sendVerificationEmail(auth.email, {
        firstName: auth.userProfile.firstName,
        verificationUrl,
      });
    } catch (error) {
      this.logger.error('Failed to resend verification email:', error);
      throw new BadRequestException('Failed to send verification email');
    }

    this.logger.log(`Verification email resent to: ${email}`);

    return { message: 'If an account with that email exists, we sent a verification email' };
  }

  async findById(id: string): Promise<Auth | null> {
    return this.authRepository.findOne({
      where: { id, isActive: true },
      relations: ['userProfile'],
    });
  }

  async findByEmail(email: string): Promise<Auth | null> {
    return this.authRepository.findOne({
      where: { email, isActive: true },
      relations: ['userProfile'],
    });
  }

  private async generateTokens(payload: Omit<JwtPayload, 'iat' | 'exp'>): Promise<JwtTokens> {
    const accessToken = this.jwtService.sign(payload, {
      secret: this.configService.get('jwt.secret'),
      expiresIn: this.configService.get('jwt.expiresIn'),
    });

    const refreshToken = this.jwtService.sign(payload, {
      secret: this.configService.get('jwt.refreshSecret'),
      expiresIn: this.configService.get('jwt.refreshExpiresIn'),
    });

    return { accessToken, refreshToken };
  }

  private generateSecureToken(): string {
    return randomBytes(32).toString('hex');
  }
}