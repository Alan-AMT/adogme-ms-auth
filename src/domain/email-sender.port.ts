export interface SendEmailParams {
  to: string | string[];
  subject: string;
  template: EmailTemplate;
  context: Record<string, any>;
}

export enum EmailTemplate {
  PASSWORD_RESET = 'password-reset',
}

export abstract class EmailSenderPort {
  abstract sendEmail(params: SendEmailParams): Promise<void>;
}
