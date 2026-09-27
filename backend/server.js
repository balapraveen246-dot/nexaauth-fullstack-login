
require("dotenv").config();

const express = require("express");
const cors = require("cors");
const session = require("express-session");
const { MongoStore } = require("connect-mongo");
const { MongoClient } = require("mongodb");
const bcrypt = require("bcrypt");
const sanitizeHtml = require("sanitize-html");

const app = express();

const PORT = process.env.PORT || 3001;
const MONGO_URI = process.env.MONGO_URI;
const SESSION_SECRET = process.env.SESSION_SECRET;
const FRONTEND_URL =
  process.env.FRONTEND_URL || "http://localhost:5173";

const isProduction = process.env.NODE_ENV === "production";

// Check required environment variables
if (!MONGO_URI || !SESSION_SECRET) {
  console.error(
    "Missing MONGO_URI or SESSION_SECRET environment variable"
  );
  process.exit(1);
}

// Trust Render's HTTPS reverse proxy
if (isProduction) {
  app.set("trust proxy", 1);
}

// Allow React frontend
app.use(
  cors({
    origin: FRONTEND_URL,
    credentials: true,
    methods: ["GET", "POST", "OPTIONS"],
    allowedHeaders: ["Content-Type"],
  })
);

app.use(express.json());
app.use(express.urlencoded({ extended: false }));

// Store sessions in MongoDB so they survive server restarts
const sessionStore = MongoStore.create({
  mongoUrl: MONGO_URI,
  dbName: "login-system",
  collectionName: "sessions",
  ttl: 24 * 60 * 60,
});

const cookieOptions = {
  httpOnly: true,
  secure: isProduction,
  sameSite: isProduction ? "none" : "lax",
  maxAge: 24 * 60 * 60 * 1000,
  path: "/",
};

app.use(
  session({
    name: "nexaauth.sid",
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    store: sessionStore,
    cookie: cookieOptions,
  })
);

// MongoDB
let client;
let usersCollection;

async function connectDB() {
  client = new MongoClient(MONGO_URI, {
    serverSelectionTimeoutMS: 10000,
  });

  await client.connect();

  const database = client.db("login-system");
  usersCollection = database.collection("users");

  await usersCollection.createIndex(
    { email: 1 },
    { unique: true }
  );

  console.log("Connected to MongoDB Atlas");
}

// Helpers
function cleanText(value) {
  return sanitizeHtml(value.trim(), {
    allowedTags: [],
    allowedAttributes: {},
  });
}

function validEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function publicUser(user) {
  return {
    name: user.name,
    email: user.email,
  };
}

function saveLoginSession(req, user, callback) {
  req.session.regenerate((error) => {
    if (error) {
      return callback(error);
    }

    req.session.name = user.name;
    req.session.email = user.email;

    req.session.save(callback);
  });
}

// Home
app.get("/", (req, res) => {
  res.json({
    success: true,
    message: "NexaAuth Backend is running",
  });
});

// Health check
app.get("/health", (req, res) => {
  res.json({
    status: "OK",
    database: usersCollection ? "Connected" : "Unavailable",
  });
});

// Profile
app.get("/profile", (req, res) => {
  if (!req.session.email) {
    return res.status(401).json({
      success: false,
      message: "Not logged in",
    });
  }

  return res.json({
    success: true,
    name: req.session.name,
    email: req.session.email,
  });
});

// Register
app.post("/register", async (req, res) => {
  try {
    const {
      name,
      email,
      password,
      confirmPassword,
    } = req.body || {};

    if (
      typeof name !== "string" ||
      typeof email !== "string" ||
      typeof password !== "string" ||
      typeof confirmPassword !== "string" ||
      !name.trim() ||
      !email.trim() ||
      !password ||
      !confirmPassword
    ) {
      return res.status(400).json({
        success: false,
        message: "All fields are required",
      });
    }

    const cleanName = cleanText(name);
    const cleanEmail = email.trim().toLowerCase();

    if (!cleanName || cleanName.length > 100) {
      return res.status(400).json({
        success: false,
        message: "Enter a valid name",
      });
    }

    if (
      cleanEmail.length > 254 ||
      !validEmail(cleanEmail)
    ) {
      return res.status(400).json({
        success: false,
        message: "Enter a valid email address",
      });
    }

    if (password.length < 8) {
      return res.status(400).json({
        success: false,
        message: "Password must contain at least 8 characters",
      });
    }

    if (Buffer.byteLength(password, "utf8") > 72) {
      return res.status(400).json({
        success: false,
        message: "Password is too long",
      });
    }

    if (password !== confirmPassword) {
      return res.status(400).json({
        success: false,
        message: "Passwords do not match",
      });
    }

    const existingUser = await usersCollection.findOne({
      email: cleanEmail,
    });

    if (existingUser) {
      return res.status(409).json({
        success: false,
        message: "Email already exists",
      });
    }

    const hashedPassword = await bcrypt.hash(
      password,
      10
    );

    const newUser = {
      name: cleanName,
      email: cleanEmail,
      password: hashedPassword,
      createdAt: new Date(),
    };

    await usersCollection.insertOne(newUser);

    saveLoginSession(req, newUser, (error) => {
      if (error) {
        console.error("Registration session error:", error.message);

        return res.status(500).json({
          success: false,
          message: "Account created, but automatic login failed",
        });
      }

      return res.status(201).json({
        success: true,
        message: "Registration successful",
        user: publicUser(newUser),
      });
    });
  } catch (error) {
    if (error.code === 11000) {
      return res.status(409).json({
        success: false,
        message: "Email already exists",
      });
    }

    console.error("Registration error:", error.message);

    return res.status(500).json({
      success: false,
      message: "Error during registration",
    });
  }
});

// Login
app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body || {};

    if (
      typeof email !== "string" ||
      typeof password !== "string" ||
      !email.trim() ||
      !password
    ) {
      return res.status(400).json({
        success: false,
        message: "Email and password are required",
      });
    }

    const cleanEmail = email.trim().toLowerCase();

    if (!validEmail(cleanEmail)) {
      return res.status(400).json({
        success: false,
        message: "Enter a valid email address",
      });
    }

    const user = await usersCollection.findOne({
      email: cleanEmail,
    });

    if (!user) {
      return res.status(401).json({
        success: false,
        message: "Invalid email or password",
      });
    }

    const passwordMatches = await bcrypt.compare(
      password,
      user.password
    );

    if (!passwordMatches) {
      return res.status(401).json({
        success: false,
        message: "Invalid email or password",
      });
    }

    saveLoginSession(req, user, (error) => {
      if (error) {
        console.error("Login session error:", error.message);

        return res.status(500).json({
          success: false,
          message: "Unable to create login session",
        });
      }

      return res.json({
        success: true,
        message: "Login successful",
        user: publicUser(user),
      });
    });
  } catch (error) {
    console.error("Login error:", error.message);

    return res.status(500).json({
      success: false,
      message: "Error during login",
    });
  }
});

// Logout
app.post("/logout", (req, res) => {
  req.session.destroy((error) => {
    if (error) {
      console.error("Logout error:", error.message);

      return res.status(500).json({
        success: false,
        message: "Logout failed",
      });
    }

    res.clearCookie("nexaauth.sid", {
      httpOnly: true,
      secure: isProduction,
      sameSite: isProduction ? "none" : "lax",
      path: "/",
    });

    return res.json({
      success: true,
      message: "Logged out successfully",
    });
  });
});

// Unexpected errors
app.use((error, req, res, next) => {
  console.error("Server error:", error.message);

  return res.status(500).json({
    success: false,
    message: "Internal server error",
  });
});

// Start server only after MongoDB connects
async function startServer() {
  try {
    await connectDB();

    app.listen(PORT, "0.0.0.0", () => {
      console.log(`Server running on port ${PORT}`);
    });
  } catch (error) {
    console.error(
      "Backend startup failed:",
      error.message
    );

    if (client) {
      await client.close();
    }

    process.exit(1);
  }
}

startServer();