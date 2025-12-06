import { createParamDecorator, ExecutionContext } from '@nestjs/common';
import { TokenPayload } from '../types';

export const GetUser = createParamDecorator(
	(_data, ctx: ExecutionContext): TokenPayload => {
		const req = ctx.switchToHttp().getRequest();
		return req.user;
	},
);
