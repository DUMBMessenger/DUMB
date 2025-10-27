export class SMTPService {
  constructor(config) {
    this.config = config;
    this.enabled = config.enabled;
    this.apiToken = config.apiToken;
    this.fromEmail = config.fromEmail;
    this.fromName = config.fromName;
    this.appUrl = config.appUrl;
  }

  async sendEmail(to, subject, html, text = '') {
    if (!this.enabled || !this.apiToken) {
      console.warn('SMTP not enabled or no API token, email not sent to:', to);
      return false;
    }

    try {
      const response = await fetch('https://send.api.mailtrap.io/api/send', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${this.apiToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          from: {
            email: this.fromEmail,
            name: this.fromName
          },
          to: [
            {
              email: to
            }
          ],
          subject: subject,
          text: text || this.htmlToText(html),
          html: html,
          category: 'Dumb Messenger'
        })
      });

      if (response.ok) {
        const result = await response.json();
        console.log('Email sent successfully:', result.message_ids);
        return true;
      } else {
        const error = await response.text();
        console.error('Email send failed:', response.status, error);
        return false;
      }
    } catch (error) {
      console.error('Email send failed:', error);
      return false;
    }
  }

  htmlToText(html) {
    return html
      .replace(/<br\s*\/?>/gi, '\n')
      .replace(/<p\s*\/?>/gi, '\n\n')
      .replace(/<[^>]*>/g, '')
      .replace(/\n\s*\n/g, '\n\n')
      .trim();
  }

  async sendVerificationEmail(email, verificationCode) {
    const subject = 'Email Verification - Dumb Messenger';
    const html = `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <h2 style="color: #333;">Email Verification</h2>
        <p>Please use the following code to verify your email address:</p>
        <div style="background: #f4f4f4; padding: 15px; text-align: center; font-size: 24px; letter-spacing: 5px; margin: 20px 0;">
          <strong>${verificationCode}</strong>
        </div>
        <p>This code will expire in 24 hours.</p>
        <hr>
        <p style="color: #666; font-size: 12px;">If you didn't request this, please ignore this email.</p>
      </div>
    `;

    return await this.sendEmail(email, subject, html);
  }

  async sendPasswordResetEmail(email, resetToken) {
    const resetLink = `${this.appUrl}/reset-password?token=${resetToken}`;
    const subject = 'Password Reset - Dumb Messenger';
    const html = `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <h2 style="color: #333;">Password Reset</h2>
        <p>Click the button below to reset your password:</p>
        <div style="text-align: center; margin: 20px 0;">
          <a href="${resetLink}" style="background: #007bff; color: white; padding: 12px 24px; text-decoration: none; border-radius: 4px; display: inline-block;">
            Reset Password
          </a>
        </div>
        <p>Or copy this link:</p>
        <p style="word-break: break-all; color: #666;">${resetLink}</p>
        <p><strong>This link will expire in 1 hour.</strong></p>
        <hr>
        <p style="color: #666; font-size: 12px;">If you didn't request a password reset, please ignore this email.</p>
      </div>
    `;

    return await this.sendEmail(email, subject, html);
  }
}
