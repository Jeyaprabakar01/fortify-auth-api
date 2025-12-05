import { Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { PrismaModule } from 'src/prisma/prisma.module';
import { OtpModule } from 'src/otp/otp.module';

@Module({
	imports: [PrismaModule, OtpModule],
	providers: [AuthService],
	controllers: [AuthController],
})
export class AuthModule {}
