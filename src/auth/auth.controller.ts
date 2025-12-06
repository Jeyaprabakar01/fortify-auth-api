import { Body, Controller, Post, Req, Res } from '@nestjs/common';
import { AuthService } from './auth.service';
import { RegisterUserDto } from './dto/register-user.dto';
import { VerifyEmailDto } from './dto/verify-email.dto';
import { LoginUserDto } from './dto/login-user.dto';
import {
	Device,
	DeviceDetails,
} from 'src/auth/decorators/device-details.decorator';
import { Request, Response } from 'express';

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
		@Res() response: Response,
	): Promise<void> {
		return this.authService.loginUser(loginUserDto, deviceDetails, response);
	}

	@Post('refresh')
	refreshToken(@Req() req: Request, @Res() response: Response): Promise<void> {
		const refreshToken = req.cookies['refresh_token'];

		return this.authService.refreshAccessToken(refreshToken, response);
	}
}
