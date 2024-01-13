import jwt from 'jsonwebtoken';
import users from '../models/auth.js';




const generateToken = (user) => {
  return jwt.sign(
    { email: user.email, id: user._id },
    process.env.JWT_SECRET,
    { expiresIn: '1h' }
  );
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

      const incorrectPassword = true; 

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
