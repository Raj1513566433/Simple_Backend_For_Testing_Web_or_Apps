const express = require("express");
const { 
  signup, 
  login, 
  refreshToken,
  logout,
  forgotPassword,
  resetPassword,
  changePassword,
  getProfile
} = require("../controllers/authController");
const authMiddleware = require("../middleware/authMiddleware");

const router = express.Router();

// Public routes
router.post("/signup", signup);
router.post("/login", login);
router.post("/refresh-token", refreshToken);
router.post("/forgot-password", forgotPassword);
router.post("/reset-password", resetPassword);

// Protected routes
router.post("/logout", authMiddleware, logout);
router.post("/change-password", authMiddleware, changePassword);
router.get("/profile", authMiddleware, getProfile);

module.exports = router;