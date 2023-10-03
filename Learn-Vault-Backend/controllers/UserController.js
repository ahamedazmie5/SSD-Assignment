const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { validationResult } = require("express-validator");
const { body, param } = require("express-validator");
const User = require("../models/User");
const dotenv = require("dotenv");

dotenv.config();

const jwtSecret = process.env.JWT_SECRET;

// Input validation middleware for registerUser
const registerValidation = [
  body("fullname")
    .isString()
    .isLength({ min: 3 })
    .withMessage("Fullname must be at least 3 characters long"),
  body("email").isEmail().withMessage("Invalid email address"),
  body("password")
    .isString()
    .isLength({ min: 7 })
    .withMessage("Password must be at least 7 characters long"),
];

const registerUser = async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { fullname, email, password, userRole, regCode } = req.body;

    // Ensure that the properties have the expected types
    if (
      typeof fullname !== "string" ||
      typeof email !== "string" ||
      typeof password !== "string" ||
      typeof userRole !== "string" ||
      typeof regCode !== "string"
    ) {
      return res.status(400).json({ errors: [{ msg: "Invalid request body" }] });
    }

    // Sanitize user inputs here if needed

    // Check if user already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ errors: [{ msg: "User already exists" }] });
    }

    const newUser = new User({
      fullname,
      regCode,
      email,
      password,
      userRole,
    });

    // Encrypt Password
    const salt = await bcrypt.genSalt(10);
    newUser.password = await bcrypt.hash(password, salt);

    await newUser.save();

    // Return JWT
    const payload = {
      user: {
        id: newUser.id,
      },
    };

    jwt.sign(payload, jwtSecret, { expiresIn: 360000 }, (err, token) => {
      if (err) {
        console.error(err.message);
        return res.status(500).send("Server error");
      }
      res.json({ token, userRole: newUser.userRole, user: newUser.fullname });
    });
  } catch (err) {
    console.error(err.message);
    res.status(500).send("Server error");
  }
};

// ... (other routes with improved validation)

module.exports = {
  getUsers,
  getUser,
  deleteUser,
  createUser,
  updateUser,
  registerUser,
  authUser,
  loginUser,
  getUsersByID,
};
