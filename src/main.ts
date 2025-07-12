import { NestFactory, Reflector } from '@nestjs/core';
import { AppModule } from './app.module';
import * as cookieParser from 'cookie-parser';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';
import { JwtAuthGuard } from './auth/guards/jwt.auth-gaurd';
import { RolesGuard } from './auth/guards/role.guard';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  const config = new DocumentBuilder().setTitle('Assana Lite API')
    .setDescription('API documentation for Assana Lite')
    .setVersion('1.0')
    .addBearerAuth()
    .build();

    const document = SwaggerModule.createDocument(app, config);
    SwaggerModule.setup('api', app, document);

    app.use(cookieParser());

    app.useGlobalGuards(new JwtAuthGuard(), new RolesGuard(new Reflector()))
    
  await app.listen(process.env.PORT ?? 3000);
}
bootstrap();
