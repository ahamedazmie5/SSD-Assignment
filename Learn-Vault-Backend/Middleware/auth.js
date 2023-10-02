const jwt = require("jsonwebtoken");

const dotenv = require("dotenv");
dotenv.config();

const jwtSecret = process.env.JWT_SECRET; // Load the JWT secret from the environment variable

module.exports = function (req, res, next) {
  //Get token from header
  //const token = req.header("x-auth-token");
  const token = req.headers.authorization.split(" ")[1];
  //Check if there is no token in the header
  if (!token) {
    return res.status(401).json({ msg: "No token, authorization denied" });
  }

  //Verify token
  try {
    const decoded = jwt.verify(token, jwtSecret);
    req.user = decoded.user;
    next();
  } catch (err) {
    res.status(401).json({ msg: "Token is not valid" });
  }
};
