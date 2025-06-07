const express = require("express");
const helmet = require("helmet");
const cors = require("cors");
const cookieParser = require("cookie-parser");
const mongoose = require("mongoose");
require("dotenv").config();

const authRouter = require("./routers/authRouter");

const app = express();

// ✅ CORS configuration for Next.js
app.use(
  cors({
    origin: "http://localhost:3000", // your frontend origin
    credentials: true, // allow cookies (important for JWT in httpOnly cookie)
  })
);

app.use(helmet());
app.use(cookieParser());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ✅ Connect to MongoDB
mongoose
  .connect(process.env.MONGO_URI)
  .then(() => {
    console.log("✅ Database connected");
  })
  .catch((err) => {
    console.error("❌ MongoDB connection error:", err.message);
  });

// ✅ Routes
app.use("/api/auth", authRouter);

app.get("/", (req, res) => {
  res.json({ message: "Hello from the server" });
});

// ✅ Start the server
app.listen(process.env.PORT || 8000, () => {
  console.log(`🚀 Server running on port ${process.env.PORT || 8000}`);
});
