import { AuthController } from "@/controllers";
import { User } from "@/models";
import { AuthService } from "@/services";
import { forwardRef, Module } from "@nestjs/common";
import { TypeOrmModule } from "@nestjs/typeorm";
import { JwtAccessModule } from "./jwt.module";
import { MailModule } from "./mail.module";
import { UserModule } from "./user.module";

@Module({
  imports: [
    TypeOrmModule.forFeature([User]),
    MailModule,
    JwtAccessModule,
    forwardRef(() => UserModule),
  ],
  controllers: [AuthController],
  providers: [AuthService],
  exports: [AuthService],
})
export class AuthModule {}
