import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { ValidationPipe } from '@nestjs/common';
import * as cookieParser from 'cookie-parser';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  app.useGlobalPipes(new ValidationPipe({
    transform: true, // Untuk transformasi otomatis tipe data
    whitelist: true, // Untuk menghapus properti yang tidak didefinisikan dalam DTO
    forbidNonWhitelisted: true, // Untuk membuang permintaan yang mengandung properti yang tidak didefinisikan dalam DTO
  }))
  app.use(cookieParser())
  await app.listen(3000);
}
bootstrap();
