require("dotenv").config();

const express = require("express");
const mongoose = require("mongoose");
const bodyParser = require("body-parser");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const { HoldingsModel } = require("./model/HoldingsModel");
const { PositionsModel } = require("./model/PositionsModel");
const { OrdersModel } = require("./model/OrdersModel");
const { UserModel } = require("./model/UserModel");

const PORT = process.env.PORT || 3002;
const uri = process.env.MONGO_URL;
const JWT_SECRET = process.env.JWT_SECRET || "your_secret_key_12345";

const app = express();

app.use(cors());
app.use(bodyParser.json());

// SIGNUP ROUTE
app.post("/signup", async (req, res) => {
  console.log("📝 Signup request:", req.body);
  
  try {
    const { name, email, phone, password } = req.body;

    // Check if user already exists
    const existingUser = await UserModel.findOne({ email });
    if (existingUser) {
      console.log("❌ Email already exists");
      return res.status(400).json({ 
        success: false,
        message: "Email already registered" 
      });
    }

    // Hash password with bcrypt
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    // Create new user
    const newUser = new UserModel({
      name,
      email,
      phone,
      password: hashedPassword,
    });

    await newUser.save();
    console.log("✅ User created successfully:", email);

    res.status(201).json({
      success: true,
      message: "Account created successfully!",
    });
  } catch (error) {
    console.error("❌ Signup error:", error);
    res.status(500).json({ 
      success: false,
      message: "Server error: " + error.message 
    });
  }
});

// LOGIN ROUTE
app.post("/login", async (req, res) => {
  console.log("🔐 Login request:", req.body.email);
  
  try {
    const { email, password } = req.body;

    // Find user
    const user = await UserModel.findOne({ email });
    if (!user) {
      console.log("❌ User not found");
      return res.status(400).json({ 
        success: false,
        message: "Invalid email or password" 
      });
    }

    // Compare password with bcrypt
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      console.log("❌ Invalid password");
      return res.status(400).json({ 
        success: false,
        message: "Invalid email or password" 
      });
    }

    // Generate JWT token
    const token = jwt.sign(
      { userId: user._id, email: user.email },
      JWT_SECRET,
      { expiresIn: "7d" }
    );

    console.log("✅ Login successful:", email);

    res.json({
      success: true,
      message: "Login successful",
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        phone: user.phone,
      },
    });
  } catch (error) {
    console.error("❌ Login error:", error);
    res.status(500).json({ 
      success: false,
      message: "Server error: " + error.message 
    });
  }
});

// =============================================
// MIDDLEWARE TO PROTECT ROUTES
// =============================================
const authMiddleware = (req, res, next) => {
  try {
    const token = req.headers.authorization?.split(" ")[1];

    if (!token) {
      return res.status(401).json({ 
        success: false,
        message: "No token, authorization denied" 
      });
    }

    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    res.status(401).json({ 
      success: false,
      message: "Token is not valid" 
    });
  }
};

// =============================================
// PROTECTED TRADING ROUTES
// =============================================

app.get("/allHoldings", authMiddleware, async (req, res) => {
  let allHoldings = await HoldingsModel.find({});
  res.json(allHoldings);
});

app.get("/allPositions", authMiddleware, async (req, res) => {
  let allPositions = await PositionsModel.find({});
  res.json(allPositions);
});

app.post("/newOrder", authMiddleware, async (req, res) => {
  let newOrder = new OrdersModel({
    name: req.body.name,
    qty: req.body.qty,
    price: req.body.price,
    mode: req.body.mode,
  });

  newOrder.save();
  res.send("Order saved!");
});

// =============================================
// START SERVER
// =============================================
app.listen(PORT, () => {
  console.log("🚀 Server started on port " + PORT);
  mongoose.connect(uri).then(() => {
    console.log("✅ MongoDB connected!");
  }).catch((err) => {
    console.error("❌ MongoDB error:", err);
  });
});