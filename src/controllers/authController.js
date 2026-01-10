const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const User = require("../models/User");

// ---- SIGNUP ----
const signup = async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ message: "Email and password are required" });
    }

    if (password.length < 6) {
      return res.status(400).json({ message: "Password must be at least 6 characters" });
    }

    const exists = await User.findOne({ email });
    if (exists) {
      return res.status(400).json({ message: "Email already exists" });
    }

    const hash = await bcrypt.hash(password, 10);

    const user = await User.create({ 
      email, 
      password: hash
    });

    return res.status(201).json({ 
      message: "Signup successful. You can now login.", 
      user: { id: user._id, email: user.email }
    });

  } catch (error) {
    console.error(error);
    res.status(500).json({ message: error.message });
  }
};

// ---- LOGIN ----
const login = async (req, res) => {
  try {
    const { email, password, variant } = req.body;

    if (!email || !password) {
      return res.status(400).json({ message: "Email and password are required" });
    }

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ message: "Invalid credentials" });
    }

    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      return res.status(400).json({ message: "Invalid credentials" });
    }

    const accessToken = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: "1d" });
    const refreshToken = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: "7d" });

    user.refreshTokens.push({ token: refreshToken });
    await user.save();

    if (variant === "A") return res.json({ accessToken });
    if (variant === "B") return res.json({ accessToken, refreshToken });
    if (variant === "C") return res.json({ accessToken, refreshToken, user: { id: user._id, email: user.email } });
    if (variant === "D") return res.json({ ...user.toObject(), accessToken });

    return res.json({ 
      message: "Login successful",
      accessToken, 
      refreshToken, 
      user: { id: user._id, email: user.email }
    });

  } catch (error) {
    console.error(error);
    return res.status(500).json({ message: "Server error" });
  }
};

// ---- REFRESH TOKEN ----
const refreshToken = async (req, res) => {
  try {
    const { refreshToken } = req.body;

    if (!refreshToken) {
      return res.status(400).json({ message: "Refresh token is required" });
    }

    const decoded = jwt.verify(refreshToken, process.env.JWT_SECRET);
    
    const user = await User.findById(decoded.id);
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    const tokenExists = user.refreshTokens.some(rt => rt.token === refreshToken);
    if (!tokenExists) {
      return res.status(403).json({ message: "Invalid refresh token" });
    }

    const newAccessToken = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: "1d" });

    return res.json({ 
      message: "Token refreshed successfully",
      accessToken: newAccessToken 
    });

  } catch (error) {
    if (error.name === 'JsonWebTokenError' || error.name === 'TokenExpiredError') {
      return res.status(403).json({ message: "Invalid or expired refresh token" });
    }
    console.error(error);
    return res.status(500).json({ message: "Server error" });
  }
};

// ---- LOGOUT ----
const logout = async (req, res) => {
  try {
    const { refreshToken } = req.body;
    const userId = req.user?.id;

    if (!userId) {
      return res.status(401).json({ message: "Unauthorized" });
    }

    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    if (refreshToken) {
      user.refreshTokens = user.refreshTokens.filter(rt => rt.token !== refreshToken);
    } else {
      user.refreshTokens = [];
    }

    await user.save();

    return res.json({ message: "Logout successful" });

  } catch (error) {
    console.error(error);
    return res.status(500).json({ message: "Server error" });
  }
};

// ---- FORGOT PASSWORD (Console e token dekhabe) ----
const forgotPassword = async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({ message: "Email is required" });
    }

    const user = await User.findOne({ email });
    if (!user) {
      return res.json({ 
        message: "If the email exists, a password reset token has been generated"
      });
    }

    const resetToken = crypto.randomBytes(32).toString('hex');
    const resetTokenHash = crypto.createHash('sha256').update(resetToken).digest('hex');

    user.resetPasswordToken = resetTokenHash;
    user.resetPasswordExpiry = new Date(Date.now() + 30 * 60 * 1000);
    await user.save();

    // Console e token dekhao (Email na pathaleo chalbe)
    console.log('🔑 PASSWORD RESET TOKEN for', email, ':', resetToken);

    return res.json({ 
      message: "Password reset token generated successfully",
      resetToken: resetToken // Testing er jonno direct pathacchi
    });

  } catch (error) {
    console.error(error);
    return res.status(500).json({ message: "Server error" });
  }
};

// ---- RESET PASSWORD ----
const resetPassword = async (req, res) => {
  try {
    const { resetToken, newPassword } = req.body;

    if (!resetToken || !newPassword) {
      return res.status(400).json({ message: "Reset token and new password are required" });
    }

    if (newPassword.length < 6) {
      return res.status(400).json({ message: "Password must be at least 6 characters" });
    }

    const resetTokenHash = crypto.createHash('sha256').update(resetToken).digest('hex');

    const user = await User.findOne({
      resetPasswordToken: resetTokenHash,
      resetPasswordExpiry: { $gt: Date.now() }
    });

    if (!user) {
      return res.status(400).json({ message: "Invalid or expired reset token" });
    }

    const hash = await bcrypt.hash(newPassword, 10);

    user.password = hash;
    user.resetPasswordToken = null;
    user.resetPasswordExpiry = null;
    user.refreshTokens = [];
    await user.save();

    return res.json({ message: "Password reset successful" });

  } catch (error) {
    console.error(error);
    return res.status(500).json({ message: "Server error" });
  }
};

// ---- CHANGE PASSWORD ----
const changePassword = async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    const userId = req.user?.id;

    if (!userId) {
      return res.status(401).json({ message: "Unauthorized" });
    }

    if (!currentPassword || !newPassword) {
      return res.status(400).json({ message: "Current password and new password are required" });
    }

    if (newPassword.length < 6) {
      return res.status(400).json({ message: "New password must be at least 6 characters" });
    }

    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    const match = await bcrypt.compare(currentPassword, user.password);
    if (!match) {
      return res.status(400).json({ message: "Current password is incorrect" });
    }

    const hash = await bcrypt.hash(newPassword, 10);

    user.password = hash;
    user.refreshTokens = [];
    await user.save();

    return res.json({ message: "Password changed successfully. Please login again." });

  } catch (error) {
    console.error(error);
    return res.status(500).json({ message: "Server error" });
  }
};

// ---- GET USER PROFILE ----
const getProfile = async (req, res) => {
  try {
    const userId = req.user?.id;

    if (!userId) {
      return res.status(401).json({ message: "Unauthorized" });
    }

    const user = await User.findById(userId).select('-password -refreshTokens -resetPasswordToken -resetPasswordExpiry');
    
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    return res.json({ user });

  } catch (error) {
    console.error(error);
    return res.status(500).json({ message: "Server error" });
  }
};

module.exports = { 
  signup, 
  login, 
  refreshToken,
  logout,
  forgotPassword,
  resetPassword,
  changePassword,
  getProfile
};