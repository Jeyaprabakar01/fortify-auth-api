import { createParamDecorator, ExecutionContext } from '@nestjs/common';
import { UAParser } from 'ua-parser-js';

export type DeviceDetails = {
	ipAddress: string;
	userAgent: string;
	deviceInfo: string;
};

export const Device = createParamDecorator(
	(_data: unknown, ctx: ExecutionContext): DeviceDetails => {
		const request = ctx.switchToHttp().getRequest();

		const ipAddress =
			request.ip ||
			request.headers['x-forwarded-for'] ||
			request.headers['x-real-ip'] ||
			request.connection.remoteAddress ||
			'';

		const userAgent = request.headers['user-agent'] || '';
		const parser = new UAParser(userAgent);
		const result = parser.getResult();

		const deviceType = result.device.type || 'desktop';
		const deviceVendor = result.device.vendor || '';
		const deviceModel = result.device.model || '';
		const browserName = result.browser.name || 'Unknown';
		const browserVersion = result.browser.version || '';
		const osName = result.os.name || 'Unknown';
		const osVersion = result.os.version || '';

		const deviceInfo =
			`${deviceVendor} ${deviceModel} ${deviceType} - ${browserName} ${browserVersion} on ${osName} ${osVersion}`.trim();

		return {
			ipAddress,
			userAgent,
			deviceInfo,
		};
	},
);
