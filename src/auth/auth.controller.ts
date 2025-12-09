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

@Controller('auth')
export class AuthController {
	constructor(private readonly authService: AuthService) {}

	@Post('register')
	registerUser(@Body() registerUserDto: RegisterUserDto): Promise<string> {
		return this.authService.registerUser(registerUserDto);
	}

	@Post('verify-email')
	verifyEmail(@Body() verifyEmailDto: VerifyEmailDto): Promise<string> {
		return this.authService.verifyEmail(verifyEmailDto);
	}

	@Post('login')
	loginUser(
		@Body() loginUserDto: LoginUserDto,
		@Device() deviceDetails: DeviceDetails,
		@Res() res: Response,
	): Promise<void> {
		return this.authService.loginUser(loginUserDto, deviceDetails, res);
	}

	@Post('refresh')
	refreshToken(@Req() req: Request, @Res() res: Response): Promise<void> {
		const refreshToken = req.cookies['refresh_token'];

		return this.authService.refreshAccessToken(refreshToken, res);
	}

	@Post('logout')
	@UseGuards(JwtAuthGuard)
	logout(
		@GetUser() tokenPayload: TokenPayload,
		@Res() res: Response,
	): Promise<void> {
		return this.authService.logout(tokenPayload.sessionId, res);
	}

	@Post('reset-password')
	resetPassword(@Body() resetPasswordDto: ResetPasswordDto): Promise<string> {
		return this.authService.resetPassword(resetPasswordDto);
	}

	@Post('update-password')
	updatePassword(
		@Body() updatePasswordDto: UpdatePasswordDto,
	): Promise<string> {
		return this.authService.updatePassword(updatePasswordDto);
	}
}
