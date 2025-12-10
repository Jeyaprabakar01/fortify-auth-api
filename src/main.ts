import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import cookieParser from 'cookie-parser';
import { ValidationPipe } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';

async function bootstrap() {
	const app = await NestFactory.create(AppModule);
	const configService = app.get(ConfigService);

	app.use(cookieParser());

	app.useGlobalPipes(
		new ValidationPipe({
			whitelist: true,
			transform: true,
		}),
	);

	const isProduction =
		configService.getOrThrow<string>('NODE_ENV') === 'production';
	app.enableCors({
		origin: isProduction
			? configService.getOrThrow<string>('WEB_APP_URL')
			: 'http://localhost:3000',
		credentials: true,
	});

	await app.listen(3001);
}
bootstrap();
