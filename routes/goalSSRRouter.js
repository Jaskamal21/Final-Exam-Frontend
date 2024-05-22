// // router.js

const express = require("express");
const router = express.Router();
// controller functions
const blogSSR = require("../controllers/goalSSRController");
const verifyToken = require("../middlewares/requireAuthSSR")

// require auth for all routes
router.use(verifyToken)

// SSR
// End1: Route to render index.html with goals using EJS
router.get("/", blogSSR.renderGoals);
// End2: Define a route to render the addgoal.ejs view
router.get("/addgoal", blogSSR.renderForm);
// End3:Route to add  goal using EJ
router.post("/addgoal", blogSSR.addGoal);
// Define a route to render the singlegoal.ejs view
router.get("/single-goal/:id", blogSSR.renderGoal);
// Define a route to delete singlegoal
router.delete("/single-goal/:id", blogSSR.deleteGoal);
// Define a route to update single goal.ejs
router.put("/single-goal/:id", blogSSR.updateGoal);
// Define goal to update
router.get("/single-goal/update/:id", blogSSR.renderUpdateGoal);

module.exports = router;