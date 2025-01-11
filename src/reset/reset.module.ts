import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { Reset } from './reset.entity';
import { ResetController } from './reset.controller';
import { ResetService } from './reset.service';

@Module({
    imports: [
        TypeOrmModule.forFeature([Reset])
    ],
    controllers: [ResetController],
    providers: [ResetService]
})
export class ResetModule {}
