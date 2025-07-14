import { Request } from 'express';
import { User } from 'src/users/Entity/user.entity';

export interface RequestWithUserProfile extends Request {
  user: User; // Ensure `User` includes the `profile` relation
}