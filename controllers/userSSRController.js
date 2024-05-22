const User = require("../models/userModel");
const jwt = require("jsonwebtoken");

const {SECRET} = require("../config/env");

const createToken = (_id) => {
  return jwt.sign({ _id }, SECRET, { expiresIn: "3d" });
};

const getLoginPage = (req, res) => {
  try {
    res.render("login", { title: "Login Page" });
  } catch (error) {
    console.error("Error rendering login.html:", error);
    res.status(500).render("error");
  }
};

// login a user
const postLogin = async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await User.login(email, password);

    // create a token
    const token = createToken(user._id);

    // Send the token as a cookie or in the response body
    res.cookie("jwt", token, {
      httpOnly: true,
      maxAge: 3 * 24 * 60 * 60 * 1000,
    });
    res.redirect("/");
  } catch (error) {
    console.error("Error rendering index.html:", error);
    res.status(500).render("error");
  }
};

const getSignupPage = async (req, res) => {
  try {
    res.render("signup", { title: "Signup Page" });
  } catch (error) {
    console.error("Error rendering signup.html:", error);
    res.status(500).render("error");
  }
};

// signup a user
const postSignup = async (req, res) => {
  const { email, password, firstName, lastName, phoneNumber, role } = req.body;

  try {
    const user = await User.signup(email, password, firstName, lastName, phoneNumber, role);

    // create a token
    const token = createToken(user._id);

    // Send the token as a cookie or in the response body
    res.cookie("jwt", token, {
      httpOnly: true,
      maxAge: 3 * 24 * 60 * 60 * 1000,
    });
    res.redirect("/");
  } catch (error) {
    console.error("Error rendering index.html:", error);
    res.status(500).render("error");
  }
};


// Logout route to clear jwt cookie
const logout=  (req, res) => {
  res.clearCookie('jwt');
  res.redirect('/user/login'); // Redirect to login page after logout
};

const deleteAllUsers= async (req, res) => {
  try {
    // Delete all users
    await User.deleteMany({});
    
    res.status(200).json({ message: 'All users have been deleted.' });
  } catch (error) {
    console.error('Error deleting users:', error);
    res.status(500).json({ error: 'Failed to delete users.' });
  }
}

module.exports = { getLoginPage, postLogin, getSignupPage, postSignup, logout, deleteAllUsers };
