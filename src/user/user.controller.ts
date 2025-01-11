import { BadRequestException, Body, Controller, Get, Post, Req, Res, UnauthorizedException } from '@nestjs/common';
import { UserService } from './user.service';
import * as bcryptjs from 'bcryptjs';
import { JwtService } from '@nestjs/jwt';
import { Request, Response } from 'express';

@Controller('')
export class UserController {
    constructor(
        private userService: UserService,
        private jwtService: JwtService
    ) { }

    @Post("/register")
    async register(@Body() body: any) {
        if (body.password !== body.password_confirm) {
            throw new BadRequestException("Password do not match!");
        }

        return this.userService.save({
            first_name: body?.first_name,
            last_name: body.last_name,
            email: body?.email,
            password: await bcryptjs.hash(body?.password, 12)
        })
    }

    @Post("/login")
    async login(
        @Body('email') email: string,
        @Body('password') password: string,
        @Res({ passthrough: true }) response: Response
    ) {
        const user = await this.userService.findOne({ email });

        if (!user) {
            throw new BadRequestException("Invalid Credentials");
        }

        const passwordMatch = await bcryptjs.compare(password, user.password)

        if (!passwordMatch) {
            throw new BadRequestException("Invalid Credentails");
        }

        const accessToken = await this.jwtService.signAsync({
            id: user.id
        }, { expiresIn: '30s' })

        const refreshToken = await this.jwtService.signAsync({
            id: user.id
        })

        response.status(200);
        response.cookie('refresh_token', refreshToken, {
            httpOnly: true,
            maxAge: 7 * 24 * 60 * 60 * 1000 //1 week
        })

        return {
            token: accessToken
        };
    }

    @Get('user')
    async User(
        @Req() request: Request
    ) {
        try {
            const accessToken = request.headers.authorization.replace('Bearer ', '');

            const {id} = await this.jwtService.verifyAsync(accessToken);

            const {password, ...data} = await this.userService.findOne({ id })

            return data;

        } catch (error) {
            throw new UnauthorizedException();
        }
    }

    @Post('refresh')
    async refresh(
        @Req() request: Request,
        @Res({passthrough: true}) response: Response
    ) {
        try {
            const refreshToken = request.cookies['refresh_token'];
            
            const { id } = await this.jwtService.verifyAsync(refreshToken);

            response.status(200);
            const token = await this.jwtService.signAsync({ id }, { expiresIn: '30s' });

            return {
                token
            };

        } catch (error) {
            throw new UnauthorizedException();
        }
    }

    @Post('logout')
    async logout(
        @Res({passthrough: true}) response: Response
    ) {
        response.clearCookie('refresh_token');

        return {
            message: 'success'
        }
    }
}
