import { Module } from "@nestjs/common";
import { ConfigModule } from "@nestjs/config";
import { JwtModule } from "@nestjs/jwt";

@Module({
    imports: [
        ConfigModule.forRoot({ envFilePath: ".env" }),
        JwtModule.register({
            secret: process.env.JWT_ACCESS_SECRET,
        }),
    ],
    exports: [
        JwtModule.register({
            secret: process.env.JWT_ACCESS_SECRET,
        }),
    ],
})
export class JwtAccessModule {}
