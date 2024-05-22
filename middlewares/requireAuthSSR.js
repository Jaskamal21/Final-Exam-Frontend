const User = require("../models/userModel");
const jwt = require("jsonwebtoken");

const {SECRET} = require("../config/env");

const verifyToken = async (req, res, next) => {
  const token = req.cookies.jwt;

  
  if (req.path === "/user/login" || req.path === "/user/signup") {
    return next();
  }

  if (token) {
    try {
      const { _id } = jwt.verify(token, SECRET);
      const user = await User.findOne({ _id }).select("_id");

      if (!user) {
        throw new Error("User not found");
      }

      req.user = user;
      next();
    } catch (error) {
      console.error("Error verifying token:", error.message);
      res.clearCookie("jwt"); // Clear invalid or expired token
      res.redirect("/user/login");
    }
  } else {
    res.redirect("/user/login");
  }
};

module.exports = verifyToken;

