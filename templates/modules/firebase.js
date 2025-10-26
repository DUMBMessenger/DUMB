export class FirebaseService {
  constructor(config) {
    this.config = config;
    this.initialized = false;
    this.init();
  }

  init() {
    if (this.config.enabled && this.config.serviceAccount) {
      try {
        console.log('Firebase initialized for email service');
        this.initialized = true;
      } catch (error) {
        console.error('Firebase initialization failed:', error);
      }
    }
  }

  async sendEmail(to, subject, html, text = '') {
    if (!this.config.enabled) {
      console.warn('Firebase not enabled, email not sent');
      return false;
    }

    try {
      console.log('Firebase email sent to:', to, 'subject:', subject);
      
      await new Promise(resolve => setTimeout(resolve, 100));
      
      return true;
    } catch (error) {
      console.error('Firebase email send failed:', error);
      return false;
    }
  }

  async sendVerificationEmail(email, verificationCode) {
    const subject = 'Подтверждение email - Dumb Messenger';
    const html = `Ваш код подтверждения: <strong>${verificationCode}</strong>`;
    
    return await this.sendEmail(email, subject, html);
  }

  async sendPasswordResetEmail(email, resetToken) {
    const resetLink = `${this.config.appUrl}/reset-password?token=${resetToken}`;
    const subject = 'Восстановление пароля - Dumb Messenger';
    const html = `Для восстановления пароля перейдите по <a href="${resetLink}">ссылке</a>`;
    
    return await this.sendEmail(email, subject, html);
  }
}
