import { CanActivate, ExecutionContext, Injectable } from "@nestjs/common";
import { Reflector } from "@nestjs/core";
import { ROLES_KEY } from "../roles/roles.decorator";
import { Role } from "../roles/roles.enum";


@Injectable()
export class RolesGuard implements CanActivate {
    constructor(private reflector: Reflector) {}

    canActivate(context: ExecutionContext): boolean {
         const requiredRoles = this.reflector.getAllAndOverride<Role[]>(
            ROLES_KEY, [context.getHandler(), context.getClass()
            ]);

        if (!requiredRoles) {
            return true; // If no roles are required, allow access
        }    
        
        const user = context.switchToHttp().getRequest().user;
        return requiredRoles.includes(user.role)
    }
}