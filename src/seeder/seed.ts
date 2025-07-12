import { NestFactory } from '@nestjs/core';
import { AppModule } from '../app.module';
import { SeederService } from './user.seeder-service';

async function bootstrap() {
  const app = await NestFactory.createApplicationContext(AppModule);
  const seeder = app.get(SeederService);
  await seeder.seedUsers();
  await app.close();
}

bootstrap();
