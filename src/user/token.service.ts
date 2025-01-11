import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Token } from './token.entity';
import { Repository } from 'typeorm';

@Injectable()
export class TokenService {
    constructor(
        @InjectRepository(Token) protected readonly tokenRepository: Repository<Token>
    ) { }

    async save(body) {
        return await this.tokenRepository.save(body);
    }

    async findOne(options) {
        return await this.tokenRepository.findOne({ where: options });
    }
}
