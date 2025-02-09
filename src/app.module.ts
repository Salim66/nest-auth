import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { UserModule } from './user/user.module';
import { ResetModule } from './reset/reset.module';

@Module({
  imports: [
    TypeOrmModule.forRoot({
      type: 'mysql',
      host: 'localhost',
      port: 3306,
      username: 'root',
      password: 'root',
      database: 'nest_auth',
      autoLoadEntities: true, // it is hamful for product because this is change automatically when we change any entity for our end. so we need desible when we deploy into production.
      synchronize: true,
    }),
    UserModule,
    ResetModule,
  ]
})
export class AppModule {}
