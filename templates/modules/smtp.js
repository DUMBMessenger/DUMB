import nodemailer from 'nodemailer';

export class SMTPService {
  constructor(config) {
    this.config = config;
    this.transporter = null;
    this.init();
  }

  init() {
    if (this.config.enabled) {
      this.transporter = nodemailer.createTransport({
        host: this.config.host,
        port: this.config.port,
        secure: this.config.secure, // true for 465, false for other ports
        auth: {
          user: this.config.auth.user,
          pass: this.config.auth.pass
        }
      });
    }
  }

  async sendEmail(to, subject, html, text = '') {
    if (!this.config.enabled) {
      console.warn('SMTP not enabled, email not sent to:', to);
      return false;
    }

    try {
      const info = await this.transporter.sendMail({
        from: `"${this.config.fromName}" <${this.config.fromEmail}>`,
        to: to,
        subject: subject,
        text: text,
        html: html
      });

      console.log('Email sent:', info.messageId);
      return true;
    } catch (error) {
      console.error('Email send failed:', error);
      return false;
    }
  }

  async sendVerificationEmail(email, verificationCode) {
    const subject = 'Подтверждение email - Dumb Messenger';
    const html = `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <h2 style="color: #333;">Подтверждение email</h2>
        <p>Для завершения регистрации введите следующий код:</p>
        <div style="background: #f4f4f4; padding: 15px; text-align: center; font-size: 24px; letter-spacing: 5px; margin: 20px 0;">
          <strong>${verificationCode}</strong>
        </div>
        <p>Код действителен в течение 24 часов.</p>
        <hr>
        <p style="color: #666; font-size: 12px;">Если вы не регистрировались, проигнорируйте это письмо.</p>
      </div>
    `;

    return await this.sendEmail(email, subject, html);
  }

  async sendPasswordResetEmail(email, resetToken) {
    const resetLink = `${this.config.appUrl}/reset-password?token=${resetToken}`;
    const subject = 'Восстановление пароля - Dumb Messenger';
    const html = `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <h2 style="color: #333;">Восстановление пароля</h2>
        <p>Для восстановления пароля перейдите по ссылке:</p>
        <div style="text-align: center; margin: 20px 0;">
          <a href="${resetLink}" style="background: #007bff; color: white; padding: 12px 24px; text-decoration: none; border-radius: 4px; display: inline-block;">
            Восстановить пароль
          </a>
        </div>
        <p>Или скопируйте ссылку:</p>
        <p style="word-break: break-all; color: #666;">${resetLink}</p>
        <p><strong>Ссылка действительна 1 час.</strong></p>
        <hr>
        <p style="color: #666; font-size: 12px;">Если вы не запрашивали восстановление пароля, проигнорируйте это письмо.</p>
      </div>
    `;

    return await this.sendEmail(email, subject, html);
  }
}
