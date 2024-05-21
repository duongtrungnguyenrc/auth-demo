import { AuthController } from '@/controllers';
import { User } from '@/models';
import { AuthService } from '@/services';
import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { JwtAccessModule } from './jwt.module';
import { MailModule } from './mail.module';

@Module({
  imports: [TypeOrmModule.forFeature([User]), MailModule, JwtAccessModule],
  controllers: [AuthController],
  providers: [AuthService],
})
export class AuthModule {}
