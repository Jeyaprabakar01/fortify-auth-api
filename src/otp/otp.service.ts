import { BadRequestException, Injectable } from '@nestjs/common';
import { OTPType } from 'generated/prisma/enums';
import { PrismaService } from 'src/prisma/prisma.service';
import * as argon2 from 'argon2';
import { OTP } from 'generated/prisma/client';

@Injectable()
export class OtpService {
	constructor(private readonly prismaService: PrismaService) {}

	async createOtp(userId: string, type: OTPType): Promise<string> {
		const now = new Date();
		const expiresAt = new Date(now.getTime() + 5 * 60000);

		await this.invalidatePreviousOtps(userId, type);

		const plainOtp = await this.generateUniqueOtp(userId);
		const hashedOtp = await this.hashData(plainOtp);

		await this.prismaService.oTP.create({
			data: {
				userId,
				otpCode: hashedOtp,
				type,
				expiresAt,
			},
		});

		return plainOtp;
	}

	async findValidOtp(
		userId: string,
		type: OTPType,
		otpCode: string,
	): Promise<OTP | null> {
		const now = new Date();

		const otps = await this.prismaService.oTP.findMany({
			where: {
				userId,
				type,
				isUsed: false,
				expiresAt: { gt: now },
			},
			orderBy: { createdAt: 'desc' },
		});

		let validOtp: OTP | null = null;

		for (const otp of otps) {
			const isValid = await this.verifyHash(otp.otpCode, otpCode);
			if (isValid) {
				validOtp = otp;
				break;
			}
		}

		if (!validOtp) {
			throw new BadRequestException('Invalid OTP');
		}

		return validOtp;
	}

	private async invalidatePreviousOtps(
		userId: string,
		type: OTPType,
	): Promise<void> {
		const now = new Date();

		await this.prismaService.oTP.updateMany({
			where: {
				userId,
				type,
				isUsed: false,
				expiresAt: { gt: now },
			},
			data: { isUsed: true },
		});
	}

	private async generateUniqueOtp(userId: string): Promise<string> {
		const now = new Date();
		const MAX_ATTEMPTS = 5;

		let plainOtp = null;

		for (let attempt = 0; attempt < MAX_ATTEMPTS; attempt++) {
			const tempOtp = this.generateRandomOtp();

			const userOtps = await this.prismaService.oTP.findMany({
				where: {
					userId,
					expiresAt: { gt: now },
				},
			});

			let isDuplicate = false;
			for (const otp of userOtps) {
				if (await this.verifyHash(otp.otpCode, tempOtp)) {
					isDuplicate = true;
					break;
				}
			}

			if (!isDuplicate) {
				plainOtp = tempOtp;
			}
		}

		return plainOtp;
	}

	private generateRandomOtp(): string {
		return Math.floor(100000 + Math.random() * 900000).toString();
	}

	private hashData(data: string): Promise<string> {
		return argon2.hash(data);
	}

	private verifyHash(hashedData: string, data: string): Promise<boolean> {
		return argon2.verify(hashedData, data);
	}
}
