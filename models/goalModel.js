const mongoose = require('mongoose');

const goalSchema = new mongoose.Schema({
  title: { type: String, required: true },
  description: { type: String, required: true },
  targetDate: { type: Date, required: true },
  achieved: { type: Boolean },
  user_id: { type: String, required: true },   
});

module.exports = mongoose.model('Goal', goalSchema);