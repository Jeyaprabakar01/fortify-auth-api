import { Body, Controller, Post, Req, Res, UseGuards } from '@nestjs/common';
import { AuthService } from './auth.service';
import { RegisterUserDto } from './dto/register-user.dto';
import { VerifyEmailDto } from './dto/verify-email.dto';
import { LoginUserDto } from './dto/login-user.dto';
import {
	Device,
	DeviceDetails,
} from 'src/auth/decorators/device-details.decorator';
import { Request, Response } from 'express';
import { JwtAuthGuard } from './guards/jwt-auth.guard';
import { GetUser } from './decorators/get-user.decorator';
import { TokenPayload } from './types';
import { ResetPasswordDto } from './dto/reset-password.dto';
import { UpdatePasswordDto } from './dto/update-password.dto';
import { minutes, Throttle } from '@nestjs/throttler';

@Controller('auth')
export class AuthController {
	constructor(private readonly authService: AuthService) {}

	@Throttle({ short: { limit: 2, ttl: minutes(1) } })
	@Throttle({ long: { limit: 3, ttl: minutes(60) } })
	@Post('register')
	registerUser(@Body() registerUserDto: RegisterUserDto): Promise<string> {
		return this.authService.registerUser(registerUserDto);
	}

	@Throttle({ short: { limit: 3, ttl: minutes(1) } })
	@Throttle({ medium: { limit: 5, ttl: minutes(15) } })
	@Post('verify-email')
	verifyEmail(@Body() verifyEmailDto: VerifyEmailDto): Promise<string> {
		return this.authService.verifyEmail(verifyEmailDto);
	}

	@Throttle({ short: { limit: 3, ttl: minutes(1) } })
	@Throttle({ medium: { limit: 5, ttl: minutes(15) } })
	@Throttle({ long: { limit: 10, ttl: minutes(60) } })
	@Post('login')
	loginUser(
		@Body() loginUserDto: LoginUserDto,
		@Device() deviceDetails: DeviceDetails,
		@Res() res: Response,
	): Promise<void> {
		return this.authService.loginUser(loginUserDto, deviceDetails, res);
	}

	@Throttle({ short: { limit: 5, ttl: minutes(1) } })
	@Throttle({ long: { limit: 20, ttl: minutes(60) } })
	@Post('refresh')
	refreshToken(@Req() req: Request, @Res() res: Response): Promise<void> {
		const refreshToken = req.cookies['refresh_token'];

		return this.authService.refreshAccessToken(refreshToken, res);
	}

	@Throttle({ short: { limit: 10, ttl: minutes(1) } })
	@Post('logout')
	@UseGuards(JwtAuthGuard)
	logout(
		@GetUser() tokenPayload: TokenPayload,
		@Res() res: Response,
	): Promise<void> {
		return this.authService.logout(tokenPayload.sessionId, res);
	}

	@Throttle({ short: { limit: 2, ttl: minutes(1) } })
	@Throttle({ long: { limit: 3, ttl: minutes(60) } })
	@Post('reset-password')
	resetPassword(@Body() resetPasswordDto: ResetPasswordDto): Promise<string> {
		return this.authService.resetPassword(resetPasswordDto);
	}

	@Throttle({ short: { limit: 3, ttl: minutes(1) } })
	@Throttle({ medium: { limit: 5, ttl: minutes(15) } })
	@Post('update-password')
	updatePassword(
		@Body() updatePasswordDto: UpdatePasswordDto,
	): Promise<string> {
		return this.authService.updatePassword(updatePasswordDto);
	}
}
