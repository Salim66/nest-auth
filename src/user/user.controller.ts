import { Body, Controller, Post } from '@nestjs/common';

@Controller('api')
export class UserController {
    @Post("/register")
    register(@Body() body: any) {
        return body;
    }
}
