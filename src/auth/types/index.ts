import { Role } from 'src/generated/prisma/enums';

export type TokenPayload = {
	id: string;
	email: string;
	role: Role;
	sessionId: string;
};
