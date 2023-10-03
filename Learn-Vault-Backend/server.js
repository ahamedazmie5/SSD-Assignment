const express = require("express");
const dotenv = require("dotenv");
const cors = require("cors");
const mongoose = require("mongoose");
const bodyParser = require("body-parser");
const helmet = require("helmet");
const csrf = require("csurf");
const cookieParser = require("cookie-parser");
const UserRoutes = require("./routes/UserRoutes");
const RegRoutes = require("./routes/RegNoRoutes");

dotenv.config();

const app = express();

app.use(express.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(
  cors({
    origin: ["http://localhost:3000"],
    credentials: true,
  })
);
app.use(cookieParser());
app.use(helmet());

const PORT = process.env.PORT || 8000;

app.listen(PORT, () =>
  console.log(`Server successfully started on: ${PORT}`)
);

mongoose.connect(
  process.env.DB_LINK,
  {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  },
  (err) => {
    if (err) {
      console.error("Failed to connect to MongoDB. Check your configuration.");
      process.exit(1);
    } else {
      console.log("Successfully Connected to MongoDB");
    }
  }
);

const csrfProtection = csrf({ cookie: true }); // Enable CSRF protection and store the token in a cookie

// Use CSRF middleware after cookie-parser
app.use(csrfProtection);

// Add a middleware to set the CSRF token in a cookie
app.use((req, res, next) => {
  res.cookie("XSRF-TOKEN", req.csrfToken());
  next();
});

// User routes
app.use("/user", UserRoutes);
app.use("/ReistrationCode", RegRoutes);
