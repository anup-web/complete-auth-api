const User = require('../models/User');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const sendEmail = require('../utils/email');

// Register User
const register = async (req, res) => {
    const { name, email, password } = req.body;
    try {
      const user = await User.create({ name, email, password });
  
      // Generate verification token
      const verificationToken = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '1d' });
      user.verificationToken = verificationToken;
      await user.save();
  
      // Send verification email
      const verificationUrl = `http://localhost:5000/api/auth/verify-email/${verificationToken}`;
      await sendEmail({
        email: user.email,
        subject: 'Email Verification',
        message: `Click the link to verify your email: ${verificationUrl}`,
      });
  
      res.status(201).json({ message: 'Registration successful. Please check your email to verify your account.' });
    } catch (error) {
      res.status(400).json({ message: error.message });
    }
  };

// Login User
const login = async (req, res) => {
    const { email, password } = req.body;
    try {
      const user = await User.findOne({ email });
      if (!user || !(await user.matchPassword(password))) {
        return res.status(401).json({ message: 'Invalid credentials' });
      }
  
      const accessToken = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: process.env.JWT_EXPIRE });
      const refreshToken = jwt.sign({ id: user._id }, process.env.REFRESH_TOKEN_SECRET, { expiresIn: process.env.REFRESH_TOKEN_EXPIRE });
  
      user.refreshToken = refreshToken;
      await user.save();
  
      res.status(200).json({ accessToken, refreshToken });
    } catch (error) {
      res.status(400).json({ message: error.message });
    }
  };

// Forgot Password
const forgotPassword = async (req, res) => {
  const { email } = req.body;
  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ message: 'User not found' });

    const resetToken = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '10m' });
    user.resetPasswordToken = resetToken;
    user.resetPasswordExpire = Date.now() + 10 * 60 * 1000; // 10 minutes
    await user.save();

    const resetUrl = `http://localhost:5000/api/auth/reset-password/${resetToken}`;
    await sendEmail({
      email: user.email,
      subject: 'Password Reset',
      message: `Click the link to reset your password: ${resetUrl}`,
    });

    res.status(200).json({ message: 'Email sent' });
  } catch (error) {
    res.status(400).json({ message: error.message });
  }
};

// In controllers/authController.js
const verifyEmail = async (req, res) => {
    const { token } = req.params;
    try {
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      const user = await User.findById(decoded.id);
  
      if (!user) return res.status(404).json({ message: 'User not found' });
      if (user.isVerified) return res.status(400).json({ message: 'Email already verified' });
  
      user.isVerified = true;
      user.verificationToken = undefined;
      await user.save();
  
      res.status(200).json({ message: 'Email verified successfully' });
    } catch (error) {
      res.status(400).json({ message: 'Invalid or expired token' });
    }
  };

  // In controllers/authController.js
const refreshToken = async (req, res) => {
    const { refreshToken } = req.body;
    if (!refreshToken) return res.status(401).json({ message: 'No refresh token provided' });
  
    try {
      const decoded = jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET);
      const user = await User.findById(decoded.id);
  
      if (!user || user.refreshToken !== refreshToken) {
        return res.status(403).json({ message: 'Invalid refresh token' });
      }
  
      const accessToken = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: process.env.JWT_EXPIRE });
      res.status(200).json({ accessToken });
    } catch (error) {
      res.status(403).json({ message: 'Invalid or expired refresh token' });
    }
  };


  // In controllers/authController.js
const resetPassword = async (req, res) => {
    const { token } = req.params;
    const { password } = req.body;
  
    try {
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      const user = await User.findById(decoded.id);
  
      if (!user || user.resetPasswordToken !== token || user.resetPasswordExpire < Date.now()) {
        return res.status(400).json({ message: 'Invalid or expired token' });
      }
  
      user.password = password;
      user.resetPasswordToken = undefined;
      user.resetPasswordExpire = undefined;
      await user.save();
  
      res.status(200).json({ message: 'Password reset successful' });
    } catch (error) {
      res.status(400).json({ message: 'Invalid or expired token' });
    }
  };

  // In controllers/authController.js
const changePassword = async (req, res) => {
    const { currentPassword, newPassword } = req.body;
    const userId = req.user.id;
  
    try {
      const user = await User.findById(userId);
      if (!user) return res.status(404).json({ message: 'User not found' });
  
      const isMatch = await user.matchPassword(currentPassword);
      if (!isMatch) return res.status(401).json({ message: 'Current password is incorrect' });
  
      user.password = newPassword;
      await user.save();
  
      res.status(200).json({ message: 'Password changed successfully' });
    } catch (error) {
      res.status(400).json({ message: error.message });
    }
  };

module.exports = { register, login, forgotPassword, verifyEmail, refreshToken, resetPassword, changePassword };