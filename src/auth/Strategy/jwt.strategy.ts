import { Injectable, UnauthorizedException } from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import { PassportStrategy } from "@nestjs/passport";
import { InjectRepository } from "@nestjs/typeorm";
import { ExtractJwt, Strategy } from "passport-jwt";
import { User } from "src/users/Entity/user.entity";
import { Repository } from "typeorm";
import { JwtPayload } from "../types/jwt-payload";


@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
    constructor(private configService: ConfigService,
        @InjectRepository(User) private  userRepo: Repository<User>
    ) {
        const secret = configService.get<string>('JWT_ACCESS_SECRET');
        if (!secret) {
            throw new Error('JWT_SECRET is not defined in the configuration');
        }
        super({
            jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
            ignoreExpiration: false,
            secretOrKey: secret,
        })
    }

    async validate(payload: JwtPayload) {
    console.log('JWT Payload:', payload);
    const user = await this.userRepo.findOne({
        where: { id: payload.id },
        relations: ['profile'],
    });
    console.log('User in JWT validate:', user);

  return user;
    }
}