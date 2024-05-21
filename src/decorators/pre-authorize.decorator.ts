import { EUserRoleType } from '@/models/enums';
import { SetMetadata } from '@nestjs/common';

export const HasRole = (...roles: EUserRoleType[]) =>
  SetMetadata('roles', roles);
