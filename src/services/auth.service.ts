import {
  BadRequestException,
  HttpException,
  Inject,
  Injectable,
  InternalServerErrorException,
  UnauthorizedException,
} from "@nestjs/common";
import { JwtService, TokenExpiredError } from "@nestjs/jwt";
import * as bcrypt from "bcrypt";
import { CreateUserDto, LoginDto } from "@/models/dtos";
import { User } from "@/models/entities";
import { RequestHandlerUtils } from "@/utils";
import { v4 as uuidv4 } from "uuid";
import { CACHE_MANAGER } from "@nestjs/cache-manager";
import { Cache } from "cache-manager";
import {
  ACCESS_TOKEN_EXPIRED_TIME,
  REFRESH_TOKEN_EXPIRED_TIME,
  TOKEN_BLACK_LIST_PREFIX,
} from "@/commons";
import { InjectRepository } from "@nestjs/typeorm";
import { Repository } from "typeorm";
import { MailerService } from "@nestjs-modules/mailer";
import { UserService } from "./user.service";

@Injectable()
export class AuthService {
  constructor(
    private jwtService: JwtService,
    private readonly mailerService: MailerService,
    private readonly userService: UserService,
    @Inject(CACHE_MANAGER) private readonly cacheManager: Cache,
    @InjectRepository(User) private readonly userRepository: Repository<User>,
  ) {}

  async signUp(newUser: CreateUserDto) {
    const { password, ...userInfo } = newUser;
    const existingUser: User | null = await this.userRepository.findOneBy({
      email: userInfo.email,
    });

    try {
      if (existingUser) {
        throw new BadRequestException("Email already exists!");
      }

      const hashedPassword: string = await bcrypt.hash(password, 10);

      const createdUser: User = await this.userRepository.create({
        password: hashedPassword,
        ...userInfo,
      });

      await this.userRepository.save(createdUser);

      this.mailerService.sendMail({
        to: createdUser.email,
        subject: "Welcome to Lexa",
        template: "register",
        context: { user: userInfo.name },
      });

      delete createdUser.password;

      return createdUser;
    } catch (error) {
      if (error instanceof HttpException) throw error;
      throw new InternalServerErrorException(error.message);
    }
  }

  async validate(emailOrUser: string | LoginDto) {
    try {
      let email: string;
      let password: string;

      if (typeof emailOrUser === "string") {
        email = emailOrUser;
      } else {
        email = emailOrUser.email;
        password = emailOrUser.password;
      }

      const { password: hashedPassword, ...existingUser } =
        await this.userRepository
          .createQueryBuilder("user")
          .addSelect("user.password")
          .where("user.email = :email", { email })
          .getOne();

      if (!existingUser) {
        throw new BadRequestException(
          "User not found. please check your email or password",
        );
      }

      if (password && !(await bcrypt.compare(password, hashedPassword))) {
        throw new BadRequestException("Invalid password");
      }

      const jwtPayload = {
        id: existingUser.id,
        role: existingUser.role,
      };

      const { accessToken, refreshToken } = this.generateTokenPair(jwtPayload);

      return {
        accessToken,
        refreshToken,
        user: existingUser,
      };
    } catch (error) {
      if (error instanceof HttpException) throw error;
      throw new InternalServerErrorException(error.message);
    }
  }

  private generateTokenPair(payload: Object) {
    const sessionId = uuidv4();

    const accessToken: string = this.jwtService.sign(
      { ...payload, sessionId },
      {
        expiresIn: ACCESS_TOKEN_EXPIRED_TIME,
      },
    );

    const refreshToken: string = this.jwtService.sign(
      { sessionId },
      {
        expiresIn: REFRESH_TOKEN_EXPIRED_TIME,
      },
    );

    return { accessToken, refreshToken };
  }

  async tokenValidate(request: Request) {
    const accessToken: string = RequestHandlerUtils.getAuthToken(request);

    try {
      try {
        this.jwtService.verify(accessToken);
      } catch (error) {
        throw new UnauthorizedException("Invalid auth token");
      }

      const existingUser: User = await this.userService.getUserFromRequest(
        request,
      );

      return existingUser;
    } catch (error) {
      if (error instanceof HttpException) throw error;
      throw new InternalServerErrorException(error.message);
    }
  }

  async reValidate(request: Request, refreshToken: string) {
    try {
      const authToken: string = RequestHandlerUtils.getAuthToken(request);

      if (await this.inBlackList(refreshToken))
        throw new BadRequestException("Invalid refresh token");

      const decodedToken = this.jwtService.verify(refreshToken);
      const { iat, exp, ...payload } = this.jwtService.decode(authToken);

      if (decodedToken["sessionId"] !== payload["sessionId"])
        throw new UnauthorizedException("Tokens session not match!");

      const currentTime = Math.floor(Date.now() / 1000);
      const refreshTokenValidTime = decodedToken["exp"] - currentTime;

      this.cacheManager.set(
        `${TOKEN_BLACK_LIST_PREFIX}${refreshToken}`,
        refreshToken,
        {
          ttl: refreshTokenValidTime,
        } as any,
      );

      const tokenPair = this.generateTokenPair(payload);

      return tokenPair;
    } catch (error) {
      throw error;
    }
  }

  async inValidate(request: Request) {
    const authToken: string = RequestHandlerUtils.getAuthToken(request);
    const decodedToken = await this.jwtService.decode(authToken);

    const currentTime = Math.floor(Date.now() / 1000);
    const tokenValidTime = decodedToken["exp"] - currentTime;

    await this.cacheManager.set(
      `${TOKEN_BLACK_LIST_PREFIX}${authToken}`,
      authToken,
      {
        ttl: tokenValidTime,
      } as any,
    );
    return "Log out successfully";
  }

  async inBlackList(token: string): Promise<boolean> {
    return await this.cacheManager.get(`${TOKEN_BLACK_LIST_PREFIX}${token}`)
      ? true
      : false;
  }

  async getBlacklistToken(token: string) {
    return await this.cacheManager.get(`${TOKEN_BLACK_LIST_PREFIX}${token}`);
  }
}
