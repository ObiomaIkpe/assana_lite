import { NestFactory, Reflector } from '@nestjs/core';
import { AppModule } from './app.module';
import * as cookieParser from 'cookie-parser';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';
import { JwtAuthGuard } from './auth/guards/jwt.auth-gaurd';
import { RolesGuard } from './auth/guards/role.guard';
import { ClassSerializerInterceptor, ValidationPipe } from '@nestjs/common';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  const config = new DocumentBuilder().setTitle('Assana Lite API')
    .setDescription('API documentation for Assana Lite')
    .setVersion('1.0')
    .addBearerAuth(
      {
        type: 'http',
        scheme: 'bearer',
        bearerFormat: 'JWT',
        in: 'header',
        name: 'Authorization',
      },
      'access-token',
    )
    .build();

    const document = SwaggerModule.createDocument(app, config);
    SwaggerModule.setup('api', app, document);

    app.useGlobalPipes(new ValidationPipe({ whitelist: true, forbidNonWhitelisted: true }));

    app.useGlobalInterceptors(new ClassSerializerInterceptor(app.get(Reflector)));


    app.use(cookieParser());

    // app.useGlobalGuards(new JwtAuthGuard(), new RolesGuard(new Reflector()))
    
  await app.listen(process.env.PORT ?? 3000);
}
bootstrap();
