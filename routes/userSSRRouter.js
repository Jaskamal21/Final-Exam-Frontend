// // router.js
const express = require("express");
const router = express.Router();

// controller functions
const { getLoginPage, postLogin, getSignupPage, postSignup,logout, deleteAllUsers } = require("../controllers/userSSRController");

router.get('/login', getLoginPage);
router.post('/login', postLogin);
router.get('/signup', getSignupPage);
router.post('/signup', postSignup);
router.get('/logout', logout);



module.exports = router;