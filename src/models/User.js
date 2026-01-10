const mongoose = require("mongoose");

const userSchema = new mongoose.Schema({
  email: { 
    type: String, 
    unique: true, 
    required: true,
    lowercase: true,
    trim: true
  },
  password: { 
    type: String, 
    required: true 
  },
  resetPasswordToken: {
    type: String,
    default: null
  },
  resetPasswordExpiry: {
    type: Date,
    default: null
  },
  refreshTokens: [{
    token: String,
    createdAt: { type: Date, default: Date.now }
  }]
}, { timestamps: true });

userSchema.pre('save', function() {
  if (this.refreshTokens && this.refreshTokens.length > 0) {
    const sevenDaysAgo = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
    this.refreshTokens = this.refreshTokens.filter(rt => rt.createdAt > sevenDaysAgo);
  }
});

module.exports = mongoose.model("User", userSchema);