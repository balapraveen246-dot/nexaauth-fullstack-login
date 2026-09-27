
const path = require("path");
const dotenv = require("dotenv");

// Load environment variables
const envResult = dotenv.config({
  path: path.join(__dirname, ".env"),
});

if (envResult.error) {
  console.error("Unable to load .env:", envResult.error.message);
  process.exit(1);
}

const express = require("express");
const cors = require("cors");
const session = require("express-session");
const { MongoClient } = require("mongodb");
const bcrypt = require("bcrypt");
const sanitizeHtml = require("sanitize-html");

const app = express();

const PORT = Number(process.env.PORT) || 3001;
const MONGO_URI = process.env.MONGO_URI;
const SESSION_SECRET = process.env.SESSION_SECRET;
const FRONTEND_URL =
  process.env.FRONTEND_URL || "http://localhost:5173";

const saltRounds = 10;

// Check environment variables
if (!MONGO_URI || !SESSION_SECRET) {
  console.error(
    "Missing MONGO_URI or SESSION_SECRET in backend/.env"
  );
  process.exit(1);
}

// Middleware
app.use(
  cors({
    origin: FRONTEND_URL,
    credentials: true,
    optionsSuccessStatus: 200,
  })
);

app.use(express.json());
app.use(express.urlencoded({ extended: false }));

// Session configuration
// MemoryStore is suitable only for local development.
app.use(
  session({
    name: "nexaauth.sid",
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      secure: false, // Local HTTP development only
      sameSite: "lax",
      maxAge: 24 * 60 * 60 * 1000,
    },
  })
);

// Database
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

// Home
app.get("/", (req, res) => {
  res.json({
    message: "NexaAuth backend is running",
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
    email: req.session.email,
    name: req.session.name,
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

    // Required fields
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

    if (password.length < 6) {
      return res.status(400).json({
        success: false,
        message: "Password must contain at least 6 characters",
      });
    }

    if (password.length > 72) {
      return res.status(400).json({
        success: false,
        message: "Password must not exceed 72 characters",
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

    // Hash password
    const hashedPassword = await bcrypt.hash(
      password,
      saltRounds
    );

    const newUser = {
      name: cleanName,
      email: cleanEmail,
      password: hashedPassword,
      createdAt: new Date(),
    };

    await usersCollection.insertOne(newUser);

    // Create a fresh session
    req.session.regenerate((error) => {
      if (error) {
        console.error("Session creation failed");
        return res.status(500).json({
          success: false,
          message: "Account created, but login failed",
        });
      }

      req.session.name = cleanName;
      req.session.email = cleanEmail;

      return req.session.save((saveError) => {
        if (saveError) {
          console.error("Session save failed");
          return res.status(500).json({
            success: false,
            message: "Account created, but login failed",
          });
        }

        return res.status(201).json({
          success: true,
          message: "Registration successful",
          user: publicUser(newUser),
        });
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

    // Use a generic message for invalid credentials.
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

    // Prevent session fixation
    req.session.regenerate((error) => {
      if (error) {
        console.error("Session creation failed");
        return res.status(500).json({
          success: false,
          message: "Unable to create session",
        });
      }

      req.session.name = user.name;
      req.session.email = user.email;

      return req.session.save((saveError) => {
        if (saveError) {
          console.error("Session save failed");
          return res.status(500).json({
            success: false,
            message: "Unable to save session",
          });
        }

        return res.status(200).json({
          success: true,
          message: "Login successful",
          user: publicUser(user),
        });
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
      secure: false,
      sameSite: "lax",
      path: "/",
    });

    return res.json({
      success: true,
      message: "Logged out successfully",
    });
  });
});

// Handle unexpected errors
app.use((error, req, res, next) => {
  console.error("Server error:", error.message);

  res.status(500).json({
    success: false,
    message: "Internal server error",
  });
});

// Start backend only after MongoDB connects
async function startServer() {
  try {
    await connectDB();

    app.listen(PORT, () => {
      console.log(
        `Server running on http://localhost:${PORT}`
      );
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