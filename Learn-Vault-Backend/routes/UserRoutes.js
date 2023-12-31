const express = require("express");
const router = express.Router();
const auth = require("../Middleware/auth");
const { check } = require("express-validator");
const {
  getUsers,
  getUser,
  deleteUser,
  createUser,
  updateUser,
  registerUser,
  authUser,
  loginUser,
  getUsersByID,
} = require("../controllers/userController");

const dotenv = require("dotenv");


dotenv.config();

const jwtSecret = process.env.JWT_SECRET; // Load the JWT secret from the environment variable

router.post("/createUser", createUser);
router.get("/getAllUsers", getUsers);
router.get("/getUserById/:id", getUser);
router.delete("/deleteUser/:id", deleteUser);
router.patch("/updateUserById/:id", updateUser);

router.post(
  "/signup",
  [
    check("Fullname", "Name is required").not().isEmpty(),
    check("email", "Please include a valid email").isEmail(),
    check(
      "password",
      "Please enter password with 6 or more characters"
    ).isLength({ min: 6 }),
  ],
  registerUser
);

router.get("/auth", auth, authUser);

router.post(
  "/signin",
  [
    check("email", "Please include a valid email").isEmail(),
    check("password", "Password is required").exists(),
  ],
  loginUser
);

module.exports = router;