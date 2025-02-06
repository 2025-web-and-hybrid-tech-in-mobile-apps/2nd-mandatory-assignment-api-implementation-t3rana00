// Import required modules
const express = require("express");
const passport = require("passport");
const JwtStrategy = require("passport-jwt").Strategy;
const extractJwt = require("passport-jwt").ExtractJwt;
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const Ajv = require("ajv");
const ajv = new Ajv();
const loginSuccessfulSchema = {
    type: "object",
    required: ["jsonWebToken"],
    properties: {
        jsonWebToken: { type: "string" }
    }
};

// Initialize Express app
const app = express();
const port = process.env.PORT || 3000;

// Middleware
app.use(express.json());
app.use(passport.initialize());

// In-memory user store (for demonstration purposes)
const users = [];
const highScores = [];

const MYSECRETJWTKEY = "mysecret";

// JWT Strategy Configuration
const optionsForJwtValidation = {
    jwtFromRequest: extractJwt.fromAuthHeaderAsBearerToken(),
    secretOrKey: MYSECRETJWTKEY,
};

// Passport JWT Strategy
passport.use(new JwtStrategy(optionsForJwtValidation, function (payload, done) {
    const user = users.find(user => user.userHandle === payload.userHandle);
    return user ? done(null, user) : done(null, false);
}));

//  Registration Route
app.post("/signup", (req, res) => {
    const { userHandle, password } = req.body;

    if (!userHandle || !password) {
        return res.status(400).json({ message: "UserHandle and password are required." });
    }
    if (userHandle.length < 6) {
        return res.status(400).json({ message: "UserHandle must be at least 6 characters." });
    }
    if (password.length < 6) {
        return res.status(400).json({ message: "Password must be at least 6 characters." });
    }
    if (users.find(u => u.userHandle === userHandle)) {
        return res.status(400).json({ message: "User already exists." });
    }

    // Hash password and store user
    const hashedPassword = bcrypt.hashSync(password, 10);
    users.push({ userHandle, password: hashedPassword });

    // Generate JWT token
    const token = jwt.sign({ userHandle }, MYSECRETJWTKEY);
    return res.status(201).json({ jsonWebToken: token });
});

//  Login Route
app.post("/login", (req, res) => {
  const { userHandle, password } = req.body;

  if (!userHandle || !password || typeof userHandle !== "string" || typeof password !== "string") {
      return res.status(400).json({ message: "Invalid request. userHandle and password must be strings." });
  }

  const user = users.find(u => u.userHandle === userHandle);
  if (!user || !bcrypt.compareSync(password, user.password)) {
      return res.status(401).json({ message: "Invalid username or password." });
  }
  
  const token = jwt.sign({ userHandle }, MYSECRETJWTKEY);
  res.status(201).json({ jsonWebToken: token });
});

// Fetch High Scores (Optional Filtering by Level and Pagination)
app.get("/high-scores", (req, res) => {
    const { level, page } = req.query;
    let filteredScores = level ? highScores.filter(score => score.level === level) : highScores;
    
    // Sort scores from highest to lowest
    filteredScores.sort((a, b) => b.score - a.score);
    
    // Pagination logic
    const pageSize = 20;
    const pageNumber = parseInt(page) || 1;
    const startIndex = (pageNumber - 1) * pageSize;
    const paginatedScores = filteredScores.slice(startIndex, startIndex + pageSize);
    
    res.status(200).json(paginatedScores);
});

//  Submit High Score (Requires Authentication)
app.post("/high-scores", passport.authenticate("jwt", { session: false }), (req, res) => {
    const { level, score, timestamp } = req.body;
    const userHandle = req.user?.userHandle;

    if (!level || !userHandle || score === undefined || !timestamp) {
        return res.status(400).json({ message: "All fields (level, userHandle, score, timestamp) are required." });
    }

    highScores.push({ level, userHandle, score, timestamp });
    res.status(201).json({ message: "High score added." });
});

//  Start & Close Functions (for Testing)
let serverInstance = null;
module.exports = {
    start: function () {
        if (!serverInstance) {
            serverInstance = app.listen(port, () => {
                console.log(`Server listening at http://localhost:${port}`);
            });
        }
    },
    close: function () {
        if (serverInstance) {
            serverInstance.close();
            serverInstance = null;
        }
    }
};

//  Start the server if this file is run directly
if (require.main === module) {
    module.exports.start();
}
