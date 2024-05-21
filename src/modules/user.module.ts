import { UserController } from "@/controllers";
import { User } from "@/models";
import { UserService } from "@/services/user.service";
import { forwardRef, Module } from "@nestjs/common";
import { TypeOrmModule } from "@nestjs/typeorm";
import { JwtAccessModule } from "./jwt.module";
import { AuthModule } from "./auth.module";

@Module({
  imports: [
    TypeOrmModule.forFeature([User]),
    JwtAccessModule,
    forwardRef(() => AuthModule),
  ],
  controllers: [UserController],
  providers: [UserService],
  exports: [UserService],
})
export class UserModule {}
