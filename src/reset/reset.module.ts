import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { Reset } from './reset.entity';
import { ResetController } from './reset.controller';
import { ResetService } from './reset.service';
import { MailerModule } from '@nestjs-modules/mailer';

@Module({
    imports: [
        TypeOrmModule.forFeature([Reset]),
        MailerModule.forRoot({
            transport: {
                host: '0.0.0.0',
                port: 1025
            },
            defaults: {
                from: 'from@example.com'
            }
        })
    ],
    controllers: [ResetController],
    providers: [ResetService]
})
export class ResetModule {}
