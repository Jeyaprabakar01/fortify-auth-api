import { IsEmail, IsNotEmpty, IsString } from 'class-validator';

export class RegisterUserDto {
	@IsNotEmpty()
	@IsString()
	readonly fullName: string;

	@IsNotEmpty()
	@IsEmail()
	readonly email: string;

	@IsNotEmpty()
	@IsString()
	readonly password: string;
}
