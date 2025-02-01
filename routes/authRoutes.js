const express = require('express');
const { register, login, forgotPassword, verifyEmail, refreshToken, resetPassword, changePassword } = require('../controllers/authController');
const router = express.Router();
const { protect, restrictTo } = require('../middleware/authMiddleware');
const limiter = require('../middleware/rateLimiter');
const { validateRegistration, validateLogin, validate } = require('../middleware/validationMiddleware');

router.post('/login', limiter, validateLogin, validate, login);
router.post('/register', limiter, validateRegistration, validate, register);
router.post('/forgot-password', forgotPassword);
router.get('/verify-email/:token', verifyEmail);
router.post('/refresh-token', refreshToken);
router.post('/reset-password/:token', resetPassword);
router.post('/change-password', protect, changePassword);
router.get('/admin-dashboard', protect, restrictTo('admin'), (req, res) => {
    res.status(200).json({ message: 'Welcome to the admin dashboard' });
  });

  

module.exports = router;