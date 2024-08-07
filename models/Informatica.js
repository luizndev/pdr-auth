// informatica.model.js
const mongoose = require("mongoose");

const informaticaSchema = new mongoose.Schema({
  id: String,
  professor: String,
  email: String,
  data: Date,
  modalidade: String,
  alunos: String,
  laboratorio: String,
  software: String,
  equipamento: String,
  observacao: String,
  token: String,
  userID: String,
  status: String,
});

const Informatica = mongoose.model("Informatica", informaticaSchema);

module.exports = Informatica;
