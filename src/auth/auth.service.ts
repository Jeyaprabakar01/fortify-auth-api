import {
	BadRequestException,
	Injectable,
	NotFoundException,
} from '@nestjs/common';
import { RegisterUserDto } from './dto/register-user.dto';
import * as argon2 from 'argon2';
import { PrismaService } from 'src/prisma/prisma.service';
import { OTPType } from 'generated/prisma/enums';
import { VerifyEmailDto } from './dto/verify-email.dto';
import { OtpService } from 'src/otp/otp.service';

@Injectable()
export class AuthService {
	constructor(
		private readonly prismaService: PrismaService,
		private readonly otpService: OtpService,
	) {}

	async registerUser(registerUserDto: RegisterUserDto): Promise<string> {
		const existingUser = await this.prismaService.user.findUnique({
			where: { email: registerUserDto.email },
		});

		if (existingUser) {
			throw new BadRequestException('User with this email already exists');
		}

		const hashedPassword = await this.hashData(registerUserDto.password);

		const user = await this.prismaService.user.create({
			data: {
				fullName: registerUserDto.fullName,
				email: registerUserDto.email,
				password: hashedPassword,
			},
		});

		const otp = await this.otpService.createOTP(user.id, OTPType.VERIFICATION);

		return otp;
	}

	async verifyEmail(verifyEmailDto: VerifyEmailDto): Promise<string> {
		const user = await this.prismaService.user.findUnique({
			where: { email: verifyEmailDto.email },
		});

		if (!user) {
			throw new NotFoundException('User not found');
		}

		if (user.isVerified) {
			throw new BadRequestException('Email already verified');
		}

		const validOtp = await this.otpService.findValidOTP(
			user.id,
			OTPType.VERIFICATION,
			verifyEmailDto.otpCode,
		);

		await this.prismaService.$transaction([
			this.prismaService.oTP.update({
				where: { id: validOtp.id },
				data: { isUsed: true },
			}),
			this.prismaService.user.update({
				where: { id: user.id },
				data: { isVerified: true },
			}),
		]);

		return 'Email verified successfully';
	}

	private hashData(data: string): Promise<string> {
		return argon2.hash(data);
	}

	private verifyHash(hashedData: string, data: string): Promise<boolean> {
		return argon2.verify(hashedData, data);
	}
}
