import { UnauthorizedException } from '@nestjs/common';

export class RequestHandlerUtils {
  static getAuthToken(request: Request): string {
    const authorizationHeader = request.headers['authorization'];
    if (!authorizationHeader)
      throw new UnauthorizedException('Invalid authorization token!');

    const [tokenType, authToken] = request.headers['authorization']?.split(' ');
    if (tokenType !== 'Bearer')
      throw new UnauthorizedException('Invalid token type!');
    if (!authToken)
      throw new UnauthorizedException('Invalid authorization token!');

    return authToken;
  }
}
