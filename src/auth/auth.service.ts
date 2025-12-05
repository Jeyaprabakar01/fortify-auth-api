import {
	BadRequestException,
	Injectable,
	NotFoundException,
	UnauthorizedException,
} from '@nestjs/common';
import { RegisterUserDto } from './dto/register-user.dto';
import * as argon2 from 'argon2';
import { PrismaService } from 'src/prisma/prisma.service';
import { VerifyEmailDto } from './dto/verify-email.dto';
import { JwtService } from '@nestjs/jwt';
import { randomBytes } from 'crypto';
import { OtpService } from 'src/otp/otp.service';
import { LoginUserDto } from './dto/login-user.dto';
import { TokenPayload } from 'src/auth/types';
import { DeviceDetails } from 'src/auth/decorators/device-details.decorator';
import { Response } from 'express';
import { OTPType } from 'src/generated/prisma/enums';

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

	async loginUser(
		loginUserDto: LoginUserDto,
		deviceDetails: DeviceDetails,
		res: Response,
	): Promise<void> {
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

		const { accessToken, refreshToken } = await this.createSession(
			user.id,
			deviceDetails,
		);

		res.cookie('access_token', accessToken, {
			httpOnly: true,
			maxAge: 15 * 60 * 1000,
			secure: true,
			sameSite: 'strict',
			path: '/',
		});

		res.cookie('refresh_token', refreshToken, {
			httpOnly: true,
			maxAge: 7 * 24 * 60 * 60 * 1000,
			secure: true,
			sameSite: 'strict',
			path: '/auth/refresh',
		});

		res.send('Logged in successfully');
	}

	private async createSession(
		userId: string,
		deviceDetails: DeviceDetails,
	): Promise<{ accessToken: string; refreshToken: string }> {
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
		const hashedRefreshToken = await this.hashData(refreshToken);

		const now = new Date();
		const expiresAt = new Date(now.getTime() + 30 * 24 * 60 * 60 * 1000);

		await this.prismaService.session.create({
			data: {
				userId: user.id,
				refreshToken: hashedRefreshToken,
				deviceInfo: deviceDetails.deviceInfo,
				ipAddress: deviceDetails.ipAddress,
				userAgent: deviceDetails.userAgent,
				lastUsedAt: now,
				expiresAt: expiresAt,
			},
		});

		return { accessToken, refreshToken };
	}

	private hashData(data: string): Promise<string> {
		return argon2.hash(data);
	}

	private verifyHash(hashedData: string, data: string): Promise<boolean> {
		return argon2.verify(hashedData, data);
	}
}
