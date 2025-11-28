import { BadRequestException, Injectable } from '@nestjs/common';
import { RegisterUserDto } from './dto/register-user.dto';
import * as argon2 from 'argon2';
import { PrismaService } from 'src/prisma/prisma.service';
import { OTPType } from 'generated/prisma/enums';
import { OTP } from 'generated/prisma/client';

@Injectable()
export class AuthService {
  constructor(private readonly prismaService: PrismaService) {}

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

    await this.createOTP(user.id, OTPType.VERIFICATION);

    return 'User registered successfully';
  }

  private hashData(password: string): Promise<string> {
    return argon2.hash(password);
  }

  private generateOTP(): Promise<string> {
    const otp = Math.floor(100000 + Math.random() * 900000).toString();

    return this.hashData(otp);
  }

  private async createOTP(userId: string, type: OTPType): Promise<OTP> {
    const now = new Date();
    const expiresAt = new Date(now.getTime() + 5 * 60000);

    await this.prismaService.oTP.updateMany({
      where: {
        userId,
        isUsed: false,
        expiresAt: { gt: now },
      },
      data: { isUsed: true },
    });

    let otpCode: string;

    while (true) {
      const tempOTP = await this.generateOTP();

      const existingOTP = await this.prismaService.oTP.findFirst({
        where: {
          otpCode: tempOTP,
          expiresAt: { gt: now },
        },
      });

      if (!existingOTP) {
        otpCode = tempOTP;
        break;
      }
    }

    const otp = await this.prismaService.oTP.create({
      data: {
        userId,
        otpCode,
        type,
        expiresAt,
      },
    });

    return otp;
  }
}
