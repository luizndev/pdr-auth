const mongoose = require("mongoose");

const messageSchema = new mongoose.Schema({
  content: { type: String, required: true },
  username: { type: String, required: true }, // Campo para o nome do usuário
  createdAt: { type: Date, default: Date.now },
});

const Message = mongoose.model("Message", messageSchema);

module.exports = Message;
