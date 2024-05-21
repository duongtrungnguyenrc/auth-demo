import { ApiTags } from "@nestjs/swagger";
import { Controller, Get, Req, UseGuards } from "@nestjs/common";
import { AuthGuard } from "@/guards";
import { UserService } from "@/services/user.service";
import { HasRole } from "@/decorators";

@Controller("user")
@ApiTags("user")
@UseGuards(AuthGuard)
export class UserController {
  constructor(private readonly userService: UserService) {}

  @Get("profile")
  @HasRole("*")
  async getProfile(@Req() request: Request) {
    return this.userService.getProfile(request);
  }
}
