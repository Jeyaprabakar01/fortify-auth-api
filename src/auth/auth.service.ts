import {
	BadRequestException,
	Injectable,
	NotFoundException,
	UnauthorizedException,
} from '@nestjs/common';
import { RegisterUserDto } from './dto/register-user.dto';
import * as argon2 from 'argon2';
import { PrismaService } from 'src/prisma/prisma.service';
import { OTPType } from 'generated/prisma/enums';
import { VerifyEmailDto } from './dto/verify-email.dto';
import { JwtService } from '@nestjs/jwt';
import { createHash, randomBytes } from 'crypto';
import { OtpService } from 'src/otp/otp.service';
import { LoginUserDto } from './dto/login-user.dto';
import { TokenPayload } from './types';

@Injectable()
export class AuthService {
	constructor(
		private readonly prismaService: PrismaService,
		private readonly jwtService: JwtService,
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

		const otp = await this.otpService.createOtp(user.id, OTPType.VERIFICATION);

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

		const validOtp = await this.otpService.findValidOtp(
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

	async loginUser(loginUserDto: LoginUserDto): Promise<string> {
		const user = await this.prismaService.user.findUnique({
			where: {
				email: loginUserDto.email,
			},
		});

		if (!user) {
			throw new UnauthorizedException('Your email or password incorrect');
		}

		if (!user.isVerified) {
			throw new UnauthorizedException(
				'Email not verified. Please verify your email',
			);
		}

		const isPasswordMatched = await this.verifyHash(
			user.password,
			loginUserDto.password,
		);

		if (!isPasswordMatched) {
			throw new UnauthorizedException('Your email or password incorrect');
		}

		return await this.createSession(user.id);
	}

	private async createSession(userId: string): Promise<string> {
		const user = await this.prismaService.user.findUnique({
			where: {
				id: userId,
			},
		});

		const tokenPayload: TokenPayload = {
			id: user.id,
			email: user.email,
			role: user.role,
		};

		const accessToken = await this.jwtService.signAsync(tokenPayload);

		const refreshToken = await randomBytes(64).toString('hex');
		const hashedRefreshToken = createHash('sha256')
			.update(refreshToken)
			.digest('hex');

		const now = new Date();
		const expiresAt = new Date(now.getTime() + 30 * 24 * 60 * 60 * 1000);

		await this.prismaService.session.create({
			data: {
				userId: user.id,
				refreshToken: hashedRefreshToken,
				deviceInfo: '',
				ipAddress: '',
				userAgent: '',
				lastUsedAt: now,
				expiresAt: expiresAt,
			},
		});

		return accessToken;
	}

	private hashData(data: string): Promise<string> {
		return argon2.hash(data);
	}

	private verifyHash(hashedData: string, data: string): Promise<boolean> {
		return argon2.verify(hashedData, data);
	}
}
