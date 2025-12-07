import { Role } from 'src/generated/prisma/enums';

export type TokenPayload = {
	id: string;
	email: string;
	role: Role;
	sessionId: string;
};

export type AuthConfig = {
	accessToken: { maxAge: number };
	refreshToken: { maxAge: number };
	session: { expiry: number; maxConcurrent: number };
	accountLock: { maxAttempts: number; lockDuration: number };
};
