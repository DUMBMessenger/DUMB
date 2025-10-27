import { SMTPService } from './smtp.js';
import { MailtrapService } from './mailtrap.js';
import { FirebaseService } from './firebase.js';

export class EmailService {
  constructor(config) {
    this.config = config;
    
    if (this.config.provider === 'mailtrap') {
      this.emailService = new MailtrapService(config.mailtrap || config.smtp);
    } else if (this.config.provider === 'smtp') {
      this.emailService = new SMTPService(config.smtp);
    } else if (this.config.provider === 'firebase') {
      this.emailService = new FirebaseService(config.firebase);
    } else {
      console.warn('No email provider configured');
      this.emailService = null;
    }
  }

  async sendVerificationEmail(email, verificationCode) {
    if (!this.emailService) {
      console.warn('Email service not configured');
      return false;
    }
    return await this.emailService.sendVerificationEmail(email, verificationCode);
  }

  async sendPasswordResetEmail(email, resetToken) {
    if (!this.emailService) {
      console.warn('Email service not configured');
      return false;
    }
    return await this.emailService.sendPasswordResetEmail(email, resetToken);
  }

  async sendEmail(to, subject, html, text = '') {
    if (!this.emailService) {
      console.warn('Email service not configured');
      return false;
    }
    return await this.emailService.sendEmail(to, subject, html, text);
  }
}
