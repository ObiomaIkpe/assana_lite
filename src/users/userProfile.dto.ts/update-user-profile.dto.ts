// src/users/dto/update-user-profile.dto.ts
import { IsOptional, IsString, IsUrl } from 'class-validator';
import { ApiPropertyOptional } from '@nestjs/swagger';

export class UpdateUserProfileDto {
  @ApiPropertyOptional()
  @IsOptional()
  @IsString()
  firstName?: string;

  @ApiPropertyOptional()
  @IsOptional()
  @IsString()
  lastName?: string;

  @ApiPropertyOptional({type: 'string', format: 'binary'})
  @IsOptional()
  @IsUrl()
  avatarUrl?: string;
}
