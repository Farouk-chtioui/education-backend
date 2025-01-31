import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import * as cookieParser from 'cookie-parser';
import * as cors from 'cors';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  // Enable CORS properly for frontend communication
  app.enableCors({
    origin: ['http://localhost:5173', 'http://localhost:3000'], // Frontend URLs
    credentials: true, // Allow cookies
  });

  app.use(cookieParser());

  await app.listen(3001);
}
bootstrap();
