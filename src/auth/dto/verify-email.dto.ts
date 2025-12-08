import { IsEmail, IsNotEmpty, IsString } from 'class-validator';

export class VerifyEmailDto {
	@IsNotEmpty()
	@IsEmail()
	readonly email: string;

	@IsNotEmpty()
	@IsString()
	readonly otpCode: string;
}
