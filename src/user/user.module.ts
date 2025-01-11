import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { User } from './user.entity';
import { UserController } from './user.controller';
import { UserService } from './user.service';
import { TokenService } from './token.service';
import { JwtModule } from '@nestjs/jwt';
import { Token } from './token.entity';

@Module({
    imports: [
        TypeOrmModule.forFeature([User, Token]),
        JwtModule.register({
            global: true,
            secret: 'secret',
            signOptions: { expiresIn: '1w' },
        }),
    ],
    controllers: [UserController],
    providers: [UserService, TokenService]
})
export class UserModule {}
