import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  app.setGlobalPrefix('api');
  app.enableCors({
    origin: ['http://localhost:3000', 'http://localhost:8080', 'http://localhost:4200'],
    credentials: true
  });
  await app.listen(process.env.PORT ?? 8000);
}
bootstrap();
