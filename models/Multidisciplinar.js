// multidisciplinar.model.js
const mongoose = require("mongoose");

const multidisciplinarSchema = new mongoose.Schema({
  id: String,
  professor: String,
  email: String,
  data: Date,
  modalidade: String,
  alunos: String,
  laboratorio: String,
  curso: String,
  turno: String,
  semestre: String,
  disciplina: String,
  tema: String,
  roteiro: String,
  observacao: String,
  token: String,
  userID: String,
  status: String,
});

const Multidisciplinar = mongoose.model(
  "Multidisciplinar",
  multidisciplinarSchema
);

module.exports = Multidisciplinar;
