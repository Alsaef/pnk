const express = require("express");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const bcrypt = require("bcrypt");
const { MongoClient } = require("mongodb");
require("dotenv").config();

const app = express();
const PORT = process.env.PORT || 5000;

// Middleware
// app.use(cors({
//   origin: ["http://localhost:5173"],
//   credentials: true,
// }));

app.use(cors({
  origin: function (origin, callback) {
    // Allow requests with no origin (like mobile apps or curl)
    if (!origin) {console.log('match'); return callback(null, true);}

    const allowedDomainPattern = /^http:\/\/([a-zA-Z0-9-]+\.)?localhost:5173$/;

    if (allowedDomainPattern.test(origin)) {
      console.log('match');
      callback(null, true);
    } else {
      console.log('cors error');
      callback(new Error("Not allowed by CORS"));
    }
  },
  credentials: true, // Allow cookies or Authorization headers
}));


app.use(express.json());
app.use(cookieParser());

// DB Connection
const client = new MongoClient(process.env.MONGO_URI);
let db, users;

async function connectDB() {
  await client.connect();
  db = client.db("shops");
  users = db.collection("users");
  console.log("Connected to MongoDB");
}

connectDB();

// 🔐 Auth Middleware
function verifyToken(req, res, next) {
  const token = req.cookies.token;
  console.log(":", req.headers,token);
  if (!token) return res.status(401).json({ message: "No token" });
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch {
    res.status(401).json({ message: "Invalid token" });
  }
}

// ✅ Signup
app.post("/api/signup", async (req, res) => {
  const { username, password, shops } = req.body;
  if (!username || !password || shops.length < 3) {
    return res.status(400).json({ message: "Invalid data" });
  }

  const exists = await users.findOne({ username });
  if (exists) return res.status(400).json({ message: "User already exists" });

  // Ensure unique shops
  const duplicateShop = await users.findOne({ shops: { $in: shops } });
  if (duplicateShop) return res.status(400).json({ message: "Shop name already taken" });

  const hashedPassword = await bcrypt.hash(password, 10);
  await users.insertOne({ username, password: hashedPassword, shops });
  res.json({ message: "Signup successful" });
});

// ✅ Signin
app.post("/api/signin", async (req, res) => {
  const { username, password, remember } = req.body;
  const user = await users.findOne({ username });
  console.log(user);
  if (!user) return res.status(401).json({ message: "User not found" });

  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch) return res.status(401).json({ message: "Incorrect password" });

  const token = jwt.sign({ username: user.username, shops: user.shops }, process.env.JWT_SECRET, {
    expiresIn: remember ? "7d" : "30m",
  });

  res.cookie("token", token, {
    httpOnly: true,
    maxAge: remember ? 7 * 24 * 60 * 60 * 1000 : 30 * 60 * 1000,
    secure:true,
    domain: ".localhost", 
    sameSite: "lax",
  });
  res.json({ message: "Signin successful" });
});

// ✅ Protected Profile Route
app.get("/api/profile",verifyToken, async (req, res) => {
  const { username, shops } = req.user;
  res.json({ username, shops });
});

// ✅ Logout
app.post("/api/logout", (req, res) => {
  res.clearCookie("token", { domain: ".localhost", sameSite: "lax" });
  res.json({ message: "Logged out" });
});

// Enhanced version with better error handling
app.get("/api/verify-shop", verifyToken, async (req, res) => {
  try {
    const { shop } = req.query;

    if (!shop) {
      return res.status(400).json({ message: "Shop name is required" });
    }

    const { shops } = req.user;
    
    if (!shops.includes(shop)) {
      return res.status(403).json({ 
        message: "Unauthorized access to shop",
        code: "SHOP_ACCESS_DENIED"
      });
    }
    
    res.json({ 
      success: true,
      shop,
      username: req.user.username,
      allShops: shops // Send all shops for potential frontend use
    });
  } catch (error) {
    console.error("Shop verification error:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ message: "Something went wrong!" });
});

// Start the server
app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));