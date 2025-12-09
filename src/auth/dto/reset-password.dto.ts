import { IsEmail, IsNotEmpty } from 'class-validator';

export class ResetPasswordDto {
	@IsNotEmpty()
	@IsEmail()
	readonly email: string;
}
