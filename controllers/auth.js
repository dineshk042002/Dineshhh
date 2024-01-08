import jwt from 'jsonwebtoken';
import users from '../models/auth.js';
import { sendSecurityAlertEmail, sendAccountBlockedEmail } from '../utils/email.js';

const MAX_FAILED_ATTEMPTS = 5;

const generateToken = (user) => {
  return jwt.sign(
    { email: user.email, id: user._id },
    process.env.JWT_SECRET,
    { expiresIn: '1h' }
  );
};

const isAccountBlocked = (blockedUntil) => {
  return blockedUntil && new Date() < new Date(blockedUntil);
};

const blockAccount = (user) => {
  user.blockedUntil = new Date(Date.now() + 60 * 60 * 1000); // Block for one hour
};

const sendSecurityAlertAndBlockEmails = async (user) => {
  if (user.failedLoginAttempts === 3) {
    await sendSecurityAlertEmail(user.email);
  }

  if (user.failedLoginAttempts === MAX_FAILED_ATTEMPTS) {
    blockAccount(user);
    await sendAccountBlockedEmail(user.email);
  }
};

export const login = async (req, res) => {
  const { email } = req.body;

  try {
    const existingUser = await users.findOne({ email });

    if (!existingUser) {
      const newUser = await users.create({ email });
      res.status(200).json({ result: newUser, token: generateToken(newUser) });
    } else {
      if (isAccountBlocked(existingUser.blockedUntil)) {
        return res.status(403).json({ mess: 'Account is blocked. Please try again later.' });
      }

      const incorrectPassword = true; // Replace this with your actual password check logic

      if (incorrectPassword) {
        existingUser.failedLoginAttempts = (existingUser.failedLoginAttempts || 0) + 1;

        await sendSecurityAlertAndBlockEmails(existingUser);

        await existingUser.save();

        return res.status(401).json({ mess: 'Incorrect email or password.' });
      } else {
        existingUser.failedLoginAttempts = 0;
        await existingUser.save();

        return res.status(200).json({ result: existingUser, token: generateToken(existingUser) });
      }
    }
  } catch (error) {
    console.error(error);
    res.status(500).json({ mess: 'Something went wrong...' });
  }
};
