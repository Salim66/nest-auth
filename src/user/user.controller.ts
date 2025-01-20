import { BadRequestException, Body, Controller, Get, Post, Req, Res, UnauthorizedException } from '@nestjs/common';
import { UserService } from './user.service';
import * as bcryptjs from 'bcryptjs';
import { JwtService } from '@nestjs/jwt';
import { Request, response, Response } from 'express';
import { TokenService } from './token.service';
import { MoreThanOrEqual } from 'typeorm';
import * as speackeasy from 'speakeasy';

@Controller('')
export class UserController {
    constructor(
        private userService: UserService,
        private jwtService: JwtService,
        private tokenService: TokenService
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

        if (!await bcryptjs.compare(password, user.password)) {
            throw new BadRequestException("Invalid Credentails");
        }

        response.status(200);

        if (user.tfa_secret) {
            return {
                id: user.id
            }
        }

        const secret = speackeasy.generateSecret({
            name: 'My App'
        })

        return {
            id: user.id,
            secret: secret.ascii,
            otpauth_url: secret.otpauth_url
        }

    }

    @Post('two-factor')
    async twoFactor(
        @Body('id') id: number,
        @Body('code') code: string,
        @Res({ passthrough: true }) response: Response,
        @Body('secret') secret: string,
    ) {
        const user = await this.userService.findOne({ id });

        if (!user) {
            throw new BadRequestException("invalid credentials");
        }

        if (!secret) {
            secret = user.tfa_secret;
        }

        const verified = speackeasy.totp.verify({
            secret,
            encoding: 'ascii',
            token: code
        });

        if (!verified) {
            throw new BadRequestException("invalid credentails");
        }

        if (user.tfa_secret === '') {
            await this.userService.update(id, {
                tfa_secret: secret
            })
        }

        const accessToken = await this.jwtService.signAsync({ id }, { expiresIn: '30s' })

        const refreshToken = await this.jwtService.signAsync({ id })

        let expired_at = new Date();
        expired_at.setDate(expired_at.getDate() + 7);

        await this.tokenService.save({
            user_id: id,
            token: refreshToken,
            expired_at
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

            const { id } = await this.jwtService.verifyAsync(accessToken);

            const { password, ...data } = await this.userService.findOne({ id })

            return data;

        } catch (error) {
            throw new UnauthorizedException();
        }
    }

    @Post('refresh')
    async refresh(
        @Req() request: Request,
        @Res({ passthrough: true }) response: Response
    ) {
        try {
            const refreshToken = request.cookies['refresh_token'];

            const { id } = await this.jwtService.verifyAsync(refreshToken);

            const tokenEntity = await this.tokenService.findOne({
                user_id: id,
                expired_at: MoreThanOrEqual(new Date)
            })

            if (!tokenEntity) {
                throw new UnauthorizedException();
            }

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
        @Req() request: Request,
        @Res({ passthrough: true }) response: Response
    ) {
        await this.tokenService.delete({ token: request.cookies['refresh_token'] });

        response.clearCookie('refresh_token');

        return {
            message: 'success'
        }
    }
}
