import { Injectable, Logger } from '@nestjs/common';
import { Resend } from 'resend';
import { EmailSenderPort, SendEmailParams, EmailTemplate } from '../../domain/email-sender.port.js';
import { ConfigService } from '@nestjs/config';
import Handlebars from 'handlebars';
import { resetPasswordTemplate } from './templates/reset-password.template.js';
import { shelterCreatedTemplate } from './templates/shelter-created.template.js';


@Injectable()
export class ResendEmailAdapter implements EmailSenderPort {
  private readonly resend: Resend;
  private readonly logger = new Logger(ResendEmailAdapter.name);
  
  constructor(private configService: ConfigService) {
    const apiKey = this.configService.get<string>('RESEND_API_KEY');
    if (!apiKey) {
      this.logger.error('RESEND_API_KEY is not defined. Email functionality will be disabled.');
    } else {
      this.resend = new Resend(apiKey);
    }
  }

  async sendEmail(params: SendEmailParams): Promise<void> {
    if (!this.resend) {
      this.logger.error('Attempted to send email but Resend client is not initialized');
      return;
    }
    try {
      const htmlContent = this.getHtmlForTemplate(params.template, params.context);

      const { data, error } = await this.resend.emails.send({
        from: 'Adogme <no-reply@adogme.org>', // Update this to your verified domain later
        to: params.to,
        subject: params.subject,
        html: htmlContent,
      });

      if (error) {
        this.logger.error(`Error sending email with Resend: ${error.message}`);
        throw new Error(`Email sending failed: ${error.message}`);
      }

      this.logger.log(`Email sent successfully: ${data?.id}`);
    } catch (err) {
      this.logger.error('Exception during email send', err);
      throw err;
    }
  }

  private getHtmlForTemplate(template: EmailTemplate, context: Record<string, any>): string {
    switch (template) {
      case EmailTemplate.PASSWORD_RESET:
        return Handlebars.compile(resetPasswordTemplate)(context);
      case EmailTemplate.SHELTER_CREATED:
        return Handlebars.compile(shelterCreatedTemplate)(context);
      default:
        return `<p>New notification from Adogme</p>`;
    }
  }
}
