import { Body, Controller, Post } from '@nestjs/common';
import { AuthService } from './auth.service';
import { RegisterUserDto } from './dto/register-user.dto';
import { VerifyEmailDto } from './dto/verify-email.dto';

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
}
