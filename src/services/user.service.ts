import { User } from "@/models";
import { RequestHandlerUtils } from "@/utils";
import { CACHE_MANAGER } from "@nestjs/cache-manager";
import { Inject, Injectable, UnauthorizedException } from "@nestjs/common";
import { JwtService } from "@nestjs/jwt";
import { InjectRepository } from "@nestjs/typeorm";
import { Repository } from "typeorm";
import { Cache } from "@nestjs/cache-manager";

@Injectable()
export class UserService {
  constructor(
    private readonly jwtService: JwtService,
    @InjectRepository(User)
    private readonly userRepository: Repository<User>,
    @Inject(CACHE_MANAGER)
    private readonly cacheManager: Cache,
  ) {}

  async getProfile(request: Request) {
    return await this.getUserFromRequest(request);
  }

  async getUserFromRequest(request: Request): Promise<User> {
    const authToken: string = RequestHandlerUtils.getAuthToken(request);
    const decodedToken: User = this.jwtService.decode(authToken);

    const cachedUser: User = await this.cacheManager.get(
      `uid_${decodedToken?.id}`,
    );

    if (cachedUser) return cachedUser;

    const user = await this.userRepository.findOneBy({
      id: decodedToken.id,
    });

    if (user)
      this.cacheManager.set(`uid_${user.id}`, user, { ttl: 180 } as any);
    else throw new UnauthorizedException("Invalid user");

    return user;
  }
}
