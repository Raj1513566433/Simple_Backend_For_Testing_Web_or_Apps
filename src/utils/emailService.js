const nodemailer = require("nodemailer");

const createTransporter = () => {
  return nodemailer.createTransport({
    host: 'smtp.gmail.com',
    port: 587,
    secure: false,
    auth: {
      user: process.env.SMTP_EMAIL,
      pass: process.env.SMTP_PASSWORD
    },
    tls: {
      rejectUnauthorized: false
    }
  });
};

const sendOTPEmail = async (email, otp) => {
  try {
    const transporter = createTransporter();

    const mailOptions = {
      from: process.env.SMTP_EMAIL,
      to: email,
      subject: 'Email Verification - OTP',
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <h2 style="color: #333;">Email Verification</h2>
          <p>Thank you for signing up! Please use the following OTP to verify your email:</p>
          <div style="background-color: #f4f4f4; padding: 20px; text-align: center; margin: 20px 0;">
            <h1 style="color: #4CAF50; letter-spacing: 5px; margin: 0;">${otp}</h1>
          </div>
          <p>This OTP will expire in 10 minutes.</p>
          <p style="color: #666; font-size: 12px;">If you didn't request this, please ignore this email.</p>
        </div>
      `
    };

    const info = await transporter.sendMail(mailOptions);
    console.log('✅ OTP email sent:', info.messageId);
    return true;
  } catch (error) {
    console.error('❌ Error sending OTP email:', error.message);
    // Development mode e email fail holew OTP console e dekhao
    if (process.env.NODE_ENV === 'development') {
      console.log('📧 DEVELOPMENT MODE - OTP:', otp);
      return true; // Email fail holew continue kore dibe
    }
    throw new Error('Failed to send OTP email');
  }
};

const sendPasswordResetEmail = async (email, resetToken) => {
  try {
    const transporter = createTransporter();

    const resetURL = `${process.env.FRONTEND_URL || 'http://localhost:3000'}/reset-password?token=${resetToken}`;

    const mailOptions = {
      from: process.env.SMTP_EMAIL,
      to: email,
      subject: 'Password Reset Request',
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <h2 style="color: #333;">Password Reset Request</h2>
          <p>You requested to reset your password. Click the button below to reset it:</p>
          <div style="text-align: center; margin: 30px 0;">
            <a href="${resetURL}" style="background-color: #4CAF50; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; display: inline-block;">Reset Password</a>
          </div>
          <p>Or copy and paste this link in your browser:</p>
          <p style="background-color: #f4f4f4; padding: 10px; word-break: break-all;">${resetURL}</p>
          <p>This link will expire in 30 minutes.</p>
          <p style="color: #666; font-size: 12px;">If you didn't request this, please ignore this email and your password will remain unchanged.</p>
        </div>
      `
    };

    const info = await transporter.sendMail(mailOptions);
    console.log('✅ Password reset email sent:', info.messageId);
    return true;
  } catch (error) {
    console.error('❌ Error sending password reset email:', error.message);
    // Development mode e email fail holew token console e dekhao
    if (process.env.NODE_ENV === 'development') {
      console.log('🔑 DEVELOPMENT MODE - Reset Token:', resetToken);
      return true; // Email fail holew continue kore dibe
    }
    throw new Error('Failed to send password reset email');
  }
};

module.exports = {
  sendOTPEmail,
  sendPasswordResetEmail
};