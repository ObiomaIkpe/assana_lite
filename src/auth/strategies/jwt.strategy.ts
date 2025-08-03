import { Injectable, UnauthorizedException } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { ConfigService } from '@nestjs/config';
import { AuthService } from '../auth.service';
import { JwtPayload } from '../interfaces/auth.interface';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor(
    private configService: ConfigService,
    private authService: AuthService,
  ) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKey: configService.get<string>('jwt.secret')!,
    });
  }

  async validate(payload: JwtPayload): Promise<JwtPayload> {
    // Verify the auth record still exists and is active
    const auth = await this.authService.findById(payload.sub);
    
    if (!auth || !auth.isActive) {
      throw new UnauthorizedException('Account not found or inactive');
    }

    // Verify email is verified for sensitive operations
    if (!auth.emailVerified) {
      throw new UnauthorizedException('Email not verified');
    }

    return {
      sub: payload.sub,
      email: payload.email,
      profileId: payload.profileId,
      organizationId: payload.organizationId,
    };
  }
}