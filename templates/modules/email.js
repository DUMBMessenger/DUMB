import { SMTPService } from './smtp.js';
import { FirebaseService } from './firebase.js';

export class EmailService {
  constructor(config) {
    this.config = config;
    this.smtpService = new SMTPService(config.smtp);
    this.firebaseService = new FirebaseService(config.firebase);
  }

  async sendVerificationEmail(email, verificationCode) {
    if (this.config.provider === 'smtp') {
      return await this.smtpService.sendVerificationEmail(email, verificationCode);
    } else if (this.config.provider === 'firebase') {
      return await this.firebaseService.sendVerificationEmail(email, verificationCode);
    }
    
    console.warn('No email provider configured');
    return false;
  }

  async sendPasswordResetEmail(email, resetToken) {
    if (this.config.provider === 'smtp') {
      return await this.smtpService.sendPasswordResetEmail(email, resetToken);
    } else if (this.config.provider === 'firebase') {
      return await this.firebaseService.sendPasswordResetEmail(email, resetToken);
    }
    
    console.warn('No email provider configured');
    return false;
  }

  async sendEmail(to, subject, html, text = '') {
    if (this.config.provider === 'smtp') {
      return await this.smtpService.sendEmail(to, subject, html, text);
    } else if (this.config.provider === 'firebase') {
      return await this.firebaseService.sendEmail(to, subject, html, text);
    }
    
    return false;
  }
}
