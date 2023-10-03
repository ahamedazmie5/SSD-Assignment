const express = require("express");
const dotenv = require("dotenv");
const cors = require("cors");
const mongoose = require("mongoose");
const bodyParser = require("body-parser");
const helmet = require("helmet"); // Import helmet middleware
const csrf = require("csurf"); // Import csurf
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

// Use the helmet middleware to remove X-Powered-By header
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

// User routes
app.use("/user", UserRoutes);
app.use("/ReistrationCode", RegRoutes);
