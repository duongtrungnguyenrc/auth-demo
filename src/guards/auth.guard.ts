import { RequestHandlerUtils } from "@/utils";
import { CanActivate, ExecutionContext, Injectable } from "@nestjs/common";
import { Reflector } from "@nestjs/core";
import { JwtService } from "@nestjs/jwt";
import { AuthService } from "@/services";

@Injectable()
export class AuthGuard implements CanActivate {
  constructor(
    private readonly reflector: Reflector,
    private readonly jwtService: JwtService,
    private readonly authService: AuthService,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const roles = this.reflector.get<string[]>("roles", context.getHandler());

    if (!roles) {
      return true;
    }

    const request = context.switchToHttp().getRequest();
    const token = RequestHandlerUtils.getAuthToken(request);

    if (!token) {
      return false;
    }

    if (await this.authService.inBlackList(token)) {
      return false;
    }
    try {
      const decodedToken = this.jwtService.verify(token);

      if (roles.includes("*")) {
        return true;
      }

      return roles.includes(decodedToken.role);
    } catch (error) {
      return false;
    }
  }
}
