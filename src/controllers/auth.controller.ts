import { HasRole } from "@/decorators";
import { AuthGuard } from "@/guards";
import { CreateUserDto, LoginDto } from "@/models/dtos";
import { AuthService } from "@/services/auth.service";
import {
  Body,
  Controller,
  HttpCode,
  Post,
  Query,
  Req,
  UseGuards,
} from "@nestjs/common";
import { ApiTags } from "@nestjs/swagger";

@ApiTags("auth")
@Controller("auth")
@UseGuards(AuthGuard)
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post("sign-up")
  async signUp(@Body() newUser: CreateUserDto) {
    return await this.authService.signUp(newUser);
  }

  @Post("sign-in")
  @HttpCode(200)
  async auth(@Body() user: LoginDto) {
    return await this.authService.validate(user);
  }

  @HasRole("ADMIN")
  @Post("sign-out")
  @HttpCode(200)
  async signOut(@Req() request: Request) {
    return await this.authService.inValidate(request);
  }

  @Post("token-auth")
  @HttpCode(200)
  async tokenAuth(
    @Req() request: Request,
  ) {
    return await this.authService.tokenValidate(request);
  }

  @HttpCode(200)
  async extendAuthSession(
    @Req() request: Request,
    @Query() refreshToken: string,
  ) {
    return await this.authService.reValidate(request, refreshToken);
  }
}
