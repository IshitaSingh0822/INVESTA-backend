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

/* =====================================================
   🌍 CORS CONFIG (FIXED)
   ===================================================== */
app.use(
  cors({
    origin: [
      "http://localhost:3000",
      "https://investa-lilac.vercel.app"
    ],
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
    credentials: true
  })
);

app.use(bodyParser.json());

/* =====================================================
   ✅ ROOT ROUTE (VERY IMPORTANT)
   ===================================================== */
app.get("/", (req, res) => {
  res.status(200).send("🚀 INVESTA Backend is running!");
});

/* =====================================================
   🔌 MONGODB CONNECTION (Vercel-safe)
   ===================================================== */
let isConnected = false;

const connectDB = async () => {
  if (isConnected) return;
  try {
    await mongoose.connect(uri);
    isConnected = true;
    console.log("✅ MongoDB connected!");
  } catch (err) {
    console.error("❌ MongoDB error:", err);
    throw err;
  }
};

app.use(async (req, res, next) => {
  try {
    await connectDB();
    next();
  } catch (err) {
    res.status(500).json({ message: "Database connection failed" });
  }
});

/* =====================================================
   SIGNUP ROUTE
   ===================================================== */
app.post("/signup", async (req, res) => {
  try {
    const { name, email, phone, password } = req.body;

    const existingUser = await UserModel.findOne({ email });
    if (existingUser) {
      return res.status(400).json({
        success: false,
        message: "Email already registered"
      });
    }

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    const newUser = new UserModel({
      name,
      email,
      phone,
      password: hashedPassword
    });

    await newUser.save();

    res.status(201).json({
      success: true,
      message: "Account created successfully!"
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Server error: " + error.message
    });
  }
});

/* =====================================================
   LOGIN ROUTE
   ===================================================== */
app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await UserModel.findOne({ email });
    if (!user) {
      return res.status(400).json({
        success: false,
        message: "Invalid email or password"
      });
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(400).json({
        success: false,
        message: "Invalid email or password"
      });
    }

    const token = jwt.sign(
      { userId: user._id, email: user.email },
      JWT_SECRET,
      { expiresIn: "7d" }
    );

    res.json({
      success: true,
      message: "Login successful",
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        phone: user.phone
      }
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Server error: " + error.message
    });
  }
});

/* =====================================================
   AUTH MIDDLEWARE
   ===================================================== */
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
  } catch {
    res.status(401).json({
      success: false,
      message: "Token is not valid"
    });
  }
};

/* =====================================================
   PROTECTED ROUTES
   ===================================================== */
app.get("/allHoldings", authMiddleware, async (req, res) => {
  const allHoldings = await HoldingsModel.find({});
  res.json(allHoldings);
});

app.get("/allPositions", authMiddleware, async (req, res) => {
  const allPositions = await PositionsModel.find({});
  res.json(allPositions);
});

app.post("/newOrder", authMiddleware, async (req, res) => {
  const newOrder = new OrdersModel({
    name: req.body.name,
    qty: req.body.qty,
    price: req.body.price,
    mode: req.body.mode
  });

  await newOrder.save();
  res.send("Order saved!");
});

/* =====================================================
   🚫 DO NOT START SERVER ON VERCEL
   ===================================================== */
// app.listen(PORT, () => {
//   console.log("🚀 Server started on port " + PORT);
// });

/* =====================================================
   ✅ EXPORT APP FOR VERCEL
   ===================================================== */
module.exports = app;
