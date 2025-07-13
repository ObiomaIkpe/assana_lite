// src/common/interfaces/request-with-user.interface.ts
import { Request } from 'express';
import { User } from '../../users/Entity/user.entity'
 // adjust path to your User entity

export interface RequestWithUser extends Request {
  user: User;
}
