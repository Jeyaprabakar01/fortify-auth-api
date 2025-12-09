import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { SmtpConfig } from './types';
import nodemailer from 'nodemailer';
import Mail from 'nodemailer/lib/mailer';

@Injectable()
export class EmailService {
	private readonly smtpConfig: SmtpConfig;

	constructor(private readonly configService: ConfigService) {
		this.smtpConfig = {
			host: this.configService.getOrThrow('SMTP_HOST'),
			port: this.configService.getOrThrow('SMTP_PORT'),
			secure: this.configService.getOrThrow('SMTP_PORT') == 465,
			auth: {
				user: this.configService.getOrThrow('SMTP_USER'),
				pass: this.configService.getOrThrow('SMTP_PASSWORD'),
			},
		};
	}

	async sendEmail(options: Mail.Options) {
		const transporter = nodemailer.createTransport(this.smtpConfig);

		try {
			await transporter.sendMail({
				from: this.smtpConfig.auth.user,
				...options,
			});
		} catch (e) {
			console.error(e);
		}
	}
}
