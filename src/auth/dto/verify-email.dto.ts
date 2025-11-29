import { IsEmail, IsNotEmpty, IsString } from 'class-validator';

export class VerifyEmailDto {
  @IsNotEmpty()
  @IsEmail()
  email: string;

  @IsNotEmpty()
  @IsString()
  otpCode: string;
}
