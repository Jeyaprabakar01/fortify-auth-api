import { Module } from '@nestjs/common';
import { OtpService } from './otp.service';
import { PrismaModule } from 'src/prisma/prisma.module';

@Module({
	imports: [PrismaModule],
	providers: [OtpService],
	exports: [OtpService],
})
export class OtpModule {}
