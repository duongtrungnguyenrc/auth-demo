import { Column, Entity } from 'typeorm';
import { BaseEntity } from './base.entity';
import { EUserRole } from '../enums';

@Entity()
export class User extends BaseEntity {
  @Column()
  name: string;

  @Column({ unique: true })
  email: string;

  @Column()
  password: string;

  @Column({
    type: 'enum',
    enum: Object.values(EUserRole),
    default: EUserRole.USER,
  })
  role: EUserRole;
}
