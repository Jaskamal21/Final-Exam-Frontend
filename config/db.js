const mongoose = require("mongoose");

const {MONGO_URI} = require("../config/env");

const connectDB = async () => {
  try {
    const conn = await mongoose.connect(MONGO_URI);
    console.log("MongoDB Connected");
  } catch (error) {
    console.error("Error connecting to MongoDB:", error.message);
    process.exit(1); // Exit with failure
  }
};

module.exports = connectDB;