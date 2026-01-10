const express = require("express");
const cors = require("cors");
const authRoutes = require("./routes/auth");

const app = express();

// middleware
app.use(cors());
app.use(express.json());

// routes
app.use("/auth", authRoutes);

module.exports = app;
