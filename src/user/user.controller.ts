import { BadRequestException, Body, Controller, Post } from '@nestjs/common';
import { UserService } from './user.service';
import * as bcryptjs from 'bcryptjs';

@Controller('api')
export class UserController {
    constructor(private userService: UserService) { }
    
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
}
