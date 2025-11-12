import nodemailer from 'nodemailer';

export class MailtrapService {
  constructor(config) {
    this.config = config;
    this.transporter = null;
    this.init();
  }

  init() {
    if (!this.config.enabled) {
      console.warn('Mailtrap disabled in configuration');
      return;
    }

    try {
      this.transporter = nodemailer.createTransport({
        host: 'send.api.mailtrap.io',
        port: 587,
        auth: {
          user: 'api',
          pass: this.config.apiToken
        }
      });
      console.log('Mailtrap transporter initialized');
    } catch (error) {
      console.error('Failed to initialize Mailtrap transporter:', error);
    }
  }

  async sendEmail(to, subject, html, text = '') {
    if (!this.transporter) {
      console.warn('Mailtrap not configured, email not sent to:', to);
      return false;
    }

    try {
      const mailOptions = {
        from: `"${this.config.fromName}" <${this.config.fromEmail}>`,
        to: Array.isArray(to) ? to : [to],
        subject: subject,
        html: html,
        text: text || this.htmlToText(html)
      };

      const info = await this.transporter.sendMail(mailOptions);
      console.log('Mailtrap email sent successfully:', info.messageId);
      return true;
    } catch (error) {
      console.error('Mailtrap email send failed:', error);
      return false;
    }
  }

  async sendVerificationEmail(email, verificationCode) {
    const subject = 'Email Verification - Dumb Messenger';
    const html = `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="utf-8">
        <style>
          body { font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; color: #333; }
          .header { text-align: center; padding: 20px 0; }
          .code { background: #f4f4f4; padding: 15px; text-align: center; font-size: 24px; letter-spacing: 5px; margin: 20px 0; border-radius: 5px; }
          .footer { margin-top: 30px; padding-top: 20px; border-top: 1px solid #ddd; color: #666; font-size: 12px; }
        </style>
      </head>
      <body>
        <div class="header">
          <h2>Email Verification</h2>
        </div>
        <p>Please use the following code to verify your email address:</p>
        <div class="code">
          <strong>${verificationCode}</strong>
        </div>
        <p>This code will expire in 24 hours.</p>
        <div class="footer">
          <p>If you didn't request this, please ignore this email.</p>
        </div>
      </body>
      </html>
    `;

    return await this.sendEmail(email, subject, html);
  }

  async sendPasswordResetEmail(email, resetToken) {
    const resetLink = `${this.config.appUrl}/reset-password?token=${resetToken}`;
    const subject = 'Password Reset - Dumb Messenger';
    const html = `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="utf-8">
        <style>
          body { font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; color: #333; }
          .header { text-align: center; padding: 20px 0; }
          .button { background: #007bff; color: white; padding: 12px 24px; text-decoration: none; border-radius: 4px; display: inline-block; }
          .link { word-break: break-all; color: #666; background: #f9f9f9; padding: 10px; border-radius: 4px; }
          .footer { margin-top: 30px; padding-top: 20px; border-top: 1px solid #ddd; color: #666; font-size: 12px; }
        </style>
      </head>
      <body>
        <div class="header">
          <h2>Password Reset</h2>
        </div>
        <p>Click the button below to reset your password:</p>
        <div style="text-align: center; margin: 20px 0;">
          <a href="${resetLink}" class="button">Reset Password</a>
        </div>
        <p>Or copy this link:</p>
        <p class="link">${resetLink}</p>
        <p><strong>This link will expire in 1 hour.</strong></p>
        <div class="footer">
          <p>If you didn't request a password reset, please ignore this email.</p>
        </div>
      </body>
      </html>
    `;

    return await this.sendEmail(email, subject, html);
  }

  htmlToText(html) {
    let result = '';
    let inTag = false;
    for (let i = 0; i < html.length; i++) {
      const char = html[i];
      if (char === '<') {
        inTag = true;
      } else if (char === '>') {
        inTag = false;
        continue;
      }
      if (!inTag) {
        result += char;
      }
    }
    result = result.replace(/\s+/g, ' ').trim();
    result = result
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;');
  
    return result;
  }
}
