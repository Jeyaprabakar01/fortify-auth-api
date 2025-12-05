import { Role } from 'generated/prisma/enums';

export type TokenPayload = {
	id: string;
	email: string;
	role: Role;
};
