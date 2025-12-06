export const authConfig = {
	accessToken: {
		expiresIn: 15 * 60 * 1000,
		maxAge: 15 * 60 * 1000,
	},
	refreshToken: {
		maxAge: 7 * 24 * 60 * 60 * 1000,
	},
	session: {
		expiresIn: 30 * 24 * 60 * 60 * 1000,
		maxSessions: 5,
	},
	accountLock: {
		maxAttempts: 5,
		lockDurationMinutes: 15,
	},
};
