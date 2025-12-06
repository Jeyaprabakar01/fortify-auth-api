import { ExtractJwt, Strategy } from 'passport-jwt';
import { PassportStrategy } from '@nestjs/passport';
import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Request } from 'express';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
	constructor(private readonly configService: ConfigService) {
		super({
			jwtFromRequest: (req: Request) => {
				const token = ExtractJwt.fromAuthHeaderAsBearerToken()(req);

				if (!token && req.cookies['access_token']) {
					return req.cookies['access_token'];
				}

				return token;
			},
			ignoreExpiration: false,
			secretOrKey: configService.getOrThrow<string>('JWT_SECRET'),
		});
	}

	async validate(payload: any) {
		return { ...payload };
	}
}
