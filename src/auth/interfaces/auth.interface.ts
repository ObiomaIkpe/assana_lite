// src/auth/interfaces/auth.interface.ts
export interface JwtPayload {
  sub: string; // auth.id
  email: string;
  profileId: string; // user_profile.id
  organizationId?: string; // current organization
  iat?: number;
  exp?: number;
}

export interface JwtTokens {
  accessToken: string;
  refreshToken: string;
}

export interface AuthResponse {
  user: {
    id: string;
    email: string;
    firstName: string;
    lastName: string;
    fullName: string;
    avatarUrl?: string;
    emailVerified: boolean;
  };
  tokens: JwtTokens;
}

export interface RequestWithUser extends Request {
  user: JwtPayload;
}

// src/auth/interfaces/email.interface.ts
export interface EmailConfig {
  host: string;
  port: number;
  user: string;
  pass: string;
  from: string;
}

export interface EmailTemplate {
  to: string;
  subject: string;
  html: string;
  text?: string;
}

export interface VerificationEmailData {
  firstName: string;
  verificationUrl: string;
}

export interface ResetPasswordEmailData {
  firstName: string;
  resetUrl: string;
}

export interface WelcomeEmailData {
  firstName: string;
  loginUrl: string;
}