import {
	BadRequestException,
	Injectable,
	UnauthorizedException,
} from '@nestjs/common';
import { RegisterUserDto } from './dto/register-user.dto';
import argon2 from 'argon2';
import { PrismaService } from 'src/prisma/prisma.service';
import { VerifyEmailDto } from './dto/verify-email.dto';
import { JwtService } from '@nestjs/jwt';
import { randomBytes, createHash, timingSafeEqual } from 'crypto';
import { OtpService } from 'src/otp/otp.service';
import { LoginUserDto } from './dto/login-user.dto';
import { TokenPayload } from 'src/auth/types';
import { DeviceDetails } from 'src/auth/decorators/device-details.decorator';
import { Response } from 'express';
import { LoginStatus, OTPType } from 'src/generated/prisma/enums';
import { authConfig } from './config/auth.config';
import { User } from 'src/generated/prisma/client';

@Injectable()
export class AuthService {
	constructor(
		private readonly prismaService: PrismaService,
		private readonly jwtService: JwtService,
		private readonly otpService: OtpService,
	) {}

	async registerUser(registerUserDto: RegisterUserDto): Promise<string> {
		await this.validateUserDoesNotExist(registerUserDto.email);

		const hashedPassword = await this.hashPassword(registerUserDto.password);

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
		const user = await this.findUserByEmail(verifyEmailDto.email);

		this.ensureEmailNotAlreadyVerified(user);

		const validOtp = await this.otpService.findValidOtp(
			user.id,
			OTPType.VERIFICATION,
			verifyEmailDto.otpCode,
		);

		await this.markEmailAsVerified(user.id, validOtp.id);

		return 'Email verified successfully';
	}

	async loginUser(
		loginUserDto: LoginUserDto,
		deviceDetails: DeviceDetails,
		res: Response,
	): Promise<void> {
		const user = await this.findUserByEmail(loginUserDto.email);

		this.ensureUserExists(user);
		this.ensureEmailIsVerified(user);

		await this.checkAccountLockStatus(user);

		const isPasswordValid = await this.verifyPassword(
			user.password,
			loginUserDto.password,
		);

		if (!isPasswordValid) {
			await this.handleFailedLogin(user.id, deviceDetails);
			return;
		}

		await this.handleSuccessfulLogin(user.id, deviceDetails, res);
	}

	async logout(sessionId: string, res: Response): Promise<void> {
		await this.prismaService.session.delete({
			where: { id: sessionId },
		});

		this.clearAuthCookies(res);

		res.send('Logged out successfully');
	}

	async refreshAccessToken(refreshToken: string, res: Response): Promise<void> {
		const session = await this.findValidSession(refreshToken);

		const newTokens = await this.rotateSessionTokens(
			session.id,
			session.userId,
		);

		this.setAuthCookies(res, newTokens.accessToken, newTokens.refreshToken);

		res.send('Token refreshed successfully');
	}

	private async validateUserDoesNotExist(email: string): Promise<void> {
		const existingUser = await this.prismaService.user.findUnique({
			where: { email },
		});

		if (existingUser) {
			throw new BadRequestException('User with this email already exists');
		}
	}

	private ensureUserExists(user: User): void {
		if (!user) {
			throw new UnauthorizedException('Invalid credentials');
		}
	}

	private ensureEmailIsVerified(user: User): void {
		if (!user.isVerified) {
			throw new UnauthorizedException(
				'Email not verified. Please verify your email',
			);
		}
	}

	private ensureEmailNotAlreadyVerified(user: User): void {
		if (user.isVerified) {
			throw new BadRequestException('Email already verified');
		}
	}

	private async findUserByEmail(email: string) {
		return this.prismaService.user.findUnique({
			where: { email },
		});
	}

	private async checkAccountLockStatus(user: User): Promise<void> {
		if (!user.lockUntil) {
			return;
		}

		const now = new Date();

		if (user.lockUntil > now) {
			const remainingMinutes = Math.ceil(
				(user.lockUntil.getTime() - now.getTime()) / (1000 * 60),
			);

			throw new UnauthorizedException(
				`Account temporarily locked. Try again in ${remainingMinutes} minute(s).`,
			);
		}

		await this.resetFailedAttempts(user.id);
	}

	private async resetFailedAttempts(userId: string): Promise<void> {
		await this.prismaService.user.update({
			where: { id: userId },
			data: {
				failedAttempts: 0,
				lockUntil: null,
			},
		});
	}

	private async handleFailedLogin(
		userId: string,
		deviceDetails: DeviceDetails,
	): Promise<never> {
		const updatedUser = await this.prismaService.user.update({
			where: { id: userId },
			data: {
				failedAttempts: { increment: 1 },
			},
			select: { failedAttempts: true },
		});

		await this.createLoginActivity(userId, deviceDetails, LoginStatus.FAILURE);

		const newFailedAttempts = updatedUser.failedAttempts;

		if (newFailedAttempts >= authConfig.accountLock.maxAttempts) {
			await this.lockAccount(userId);
			throw new UnauthorizedException(
				`Account locked due to multiple failed attempts. Try again after ${authConfig.accountLock.lockDurationMinutes} minutes.`,
			);
		}

		const remainingAttempts =
			authConfig.accountLock.maxAttempts - newFailedAttempts;

		throw new UnauthorizedException(
			`Invalid credentials. ${remainingAttempts} attempt(s) remaining.`,
		);
	}

	private async lockAccount(userId: string): Promise<void> {
		const lockUntil = new Date();
		lockUntil.setMinutes(
			lockUntil.getMinutes() + authConfig.accountLock.lockDurationMinutes,
		);

		await this.prismaService.user.update({
			where: { id: userId },
			data: { lockUntil },
		});
	}

	private async handleSuccessfulLogin(
		userId: string,
		deviceDetails: DeviceDetails,
		res: Response,
	): Promise<void> {
		await this.prismaService.$transaction(async (tx) => {
			await this.enforceSessionLimit(userId, tx);

			const { accessToken, refreshToken } = await this.createSession(
				userId,
				deviceDetails,
				tx,
			);

			await this.createLoginActivity(
				userId,
				deviceDetails,
				LoginStatus.SUCCESS,
				tx,
			);

			await tx.user.update({
				where: { id: userId },
				data: {
					failedAttempts: 0,
					lockUntil: null,
				},
			});

			this.setAuthCookies(res, accessToken, refreshToken);
		});

		res.send('Logged in successfully');
	}

	private async createSession(
		userId: string,
		deviceDetails: DeviceDetails,
		tx?: any,
	): Promise<{ accessToken: string; refreshToken: string }> {
		const prisma = tx || this.prismaService;

		const user = await prisma.user.findUnique({
			where: { id: userId },
		});

		const refreshToken = this.generateRefreshToken();
		const hashedRefreshToken = this.hashRefreshToken(refreshToken);

		const now = new Date();
		const expiresAt = new Date(now.getTime() + authConfig.session.expiresIn);

		const session = await prisma.session.create({
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

		const tokenPayload: TokenPayload = {
			id: user.id,
			email: user.email,
			role: user.role,
			sessionId: session.id,
		};

		const accessToken = await this.jwtService.signAsync(tokenPayload);

		return { accessToken, refreshToken };
	}

	private async enforceSessionLimit(userId: string, tx?: any): Promise<void> {
		const prisma = tx || this.prismaService;

		const sessions = await prisma.session.findMany({
			where: { userId },
			orderBy: { lastUsedAt: 'desc' },
		});

		if (sessions.length >= authConfig.session.maxSessions) {
			const sessionsToDelete = sessions.slice(
				authConfig.session.maxSessions - 1,
			);

			await prisma.session.deleteMany({
				where: {
					id: { in: sessionsToDelete.map((s) => s.id) },
				},
			});
		}
	}

	private async findValidSession(refreshToken: string) {
		const hashedToken = this.hashRefreshToken(refreshToken);

		const sessions = await this.prismaService.session.findMany({
			where: {
				expiresAt: { gt: new Date() },
			},
		});

		const matchingSession = sessions.find((session) => {
			try {
				const sessionBuffer = Buffer.from(session.refreshToken, 'hex');
				const tokenBuffer = Buffer.from(hashedToken, 'hex');

				if (sessionBuffer.length !== tokenBuffer.length) {
					return false;
				}

				return timingSafeEqual(
					new Uint8Array(sessionBuffer),
					new Uint8Array(tokenBuffer),
				);
			} catch {
				return false;
			}
		});

		if (!matchingSession) {
			throw new UnauthorizedException('Invalid or expired refresh token');
		}

		return matchingSession;
	}

	private async rotateSessionTokens(
		sessionId: string,
		userId: string,
	): Promise<{ accessToken: string; refreshToken: string }> {
		const user = await this.prismaService.user.findUnique({
			where: { id: userId },
		});

		const newRefreshToken = this.generateRefreshToken();
		const hashedNewToken = this.hashRefreshToken(newRefreshToken);

		const session = await this.prismaService.session.update({
			where: { id: sessionId },
			data: {
				refreshToken: hashedNewToken,
				lastUsedAt: new Date(),
			},
		});

		const tokenPayload: TokenPayload = {
			id: user.id,
			email: user.email,
			role: user.role,
			sessionId: session.id,
		};

		const accessToken = await this.jwtService.signAsync(tokenPayload);

		return { accessToken, refreshToken: newRefreshToken };
	}

	private async createLoginActivity(
		userId: string,
		deviceDetails: DeviceDetails,
		status: LoginStatus,
		tx?: any,
	): Promise<void> {
		const prisma = tx || this.prismaService;

		await prisma.loginActivity.create({
			data: {
				userId,
				ipAddress: deviceDetails.ipAddress,
				userAgent: deviceDetails.userAgent,
				deviceInfo: deviceDetails.deviceInfo,
				status: status,
			},
		});
	}

	private async markEmailAsVerified(
		userId: string,
		otpId: string,
	): Promise<void> {
		await this.prismaService.$transaction([
			this.prismaService.oTP.update({
				where: { id: otpId },
				data: { isUsed: true },
			}),
			this.prismaService.user.update({
				where: { id: userId },
				data: { isVerified: true },
			}),
		]);
	}

	private async hashPassword(password: string): Promise<string> {
		return argon2.hash(password);
	}

	private async verifyPassword(
		hashedPassword: string,
		plainPassword: string,
	): Promise<boolean> {
		return argon2.verify(hashedPassword, plainPassword);
	}

	private generateRefreshToken(): string {
		return randomBytes(64).toString('hex');
	}

	private hashRefreshToken(token: string): string {
		return createHash('sha256').update(token).digest('hex');
	}

	private setAuthCookies(
		res: Response,
		accessToken: string,
		refreshToken: string,
	): void {
		res.cookie('access_token', accessToken, {
			httpOnly: true,
			maxAge: authConfig.accessToken.maxAge,
			secure: true,
			sameSite: 'lax',
			path: '/',
		});

		res.cookie('refresh_token', refreshToken, {
			httpOnly: true,
			maxAge: authConfig.refreshToken.maxAge,
			secure: true,
			sameSite: 'lax',
			path: '/auth/refresh',
		});
	}

	private clearAuthCookies(res: Response): void {
		res.clearCookie('access_token');
		res.clearCookie('refresh_token');
	}
}
