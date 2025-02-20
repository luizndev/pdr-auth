const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const dns = require("dns");
const cors = require("cors");
const mongoose = require("mongoose");
const nodemailer = require("nodemailer");
require("dotenv").config();

const app = express();
app.use(express.json());
app.use(cors());

mongoose.connect(
  `mongodb+srv://${process.env.MONGO_USER}:${process.env.MONGO_PASS}@${process.env.MONGO_CLUSTER_URL}/${process.env.MONGO_DATABASE}?retryWrites=true&w=majority`,
  {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  }
);

const sendRecoveryEmail = async (email, token) => {
  const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASS,
    },
  });

  const mailOptions = {
    from: process.env.EMAIL_USER,
    to: email,
    subject: "Portal de Reservas | Recuperação de Senha",
    html: `
      <div style="font-family: Arial, sans-serif; text-align: center; padding: 20px; border: 1px solid #ddd; border-radius: 10px; max-width: 500px; margin: auto;">
        <h2 style="color: #333;">Recuperação de Senha</h2>
        <p style="color: #555;">Recebemos uma solicitação para redefinir sua senha.</p>
        <p style="color: #555;">Clique no botão abaixo para criar uma nova senha:</p>
        <a href="https://anhangueratx-pdr-v2.vercel.app/recover/${token}" 
          style="display: inline-block; background-color:rgb(255, 85, 0); color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; font-weight: bold;">
          Redefinir Senha
        </a>
        <p style="color: #777; font-size: 14px; margin-top: 20px;">
          Se você não solicitou essa alteração, ignore este e-mail.
        </p>
      </div>
    `,
  };

  return transporter.sendMail(mailOptions);
};


app.post("/auth/recover", async (req, res) => {
  const { email } = req.body;

  if (!email) {
    return res.status(400).json({ message: "Email é obrigatório" });
  }

  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ message: "Usuário não encontrado" });
    }

    const secret = process.env.SECRET;
    const token = jwt.sign({ id: user._id }, secret, { expiresIn: "1h" });

    await sendRecoveryEmail(email, token);

    res.status(200).json({ message: "Link de recuperação enviado para o seu e-mail" });
  } catch (error) {
    console.error("Erro ao enviar e-mail:", error);
    res.status(500).json({ message: "Erro ao enviar e-mail de recuperação" });
  }
});

app.post("/auth/recover/:token", async (req, res) => {
  const { token } = req.params;
  const { password, confirmpassword } = req.body;

  if (!password || !confirmpassword) {
    return res.status(400).json({ message: "Preencha todos os campos" });
  }

  if (password !== confirmpassword) {
    return res.status(400).json({ message: "As senhas não conferem" });
  }

  try {
    const secret = process.env.SECRET;
    const decoded = jwt.verify(token, secret);

    const user = await User.findById(decoded.id);
    if (!user) {
      return res.status(404).json({ message: "Usuário não encontrado" });
    }

    const salt = await bcrypt.genSalt(12);
    const passwordHash = await bcrypt.hash(password, salt);

    user.password = passwordHash;
    await user.save();

    res.status(200).json({ message: "Senha alterada com sucesso" });
  } catch (error) {
    res.status(500).json({ message: "Erro ao recuperar a senha" });
  }
});


// Define Mongoose schemas
const informaticaSchema = new mongoose.Schema({
  professor: String,
  email: String,
  data: String,
  modalidade: String,
  alunos: String,
  laboratorio: String,
  software: String,
  equipamento: String,
  observacao: String,
  token: String,
  userID: String,
  status: { type: String, default: "Aguardando Confirmação" },
});

const multidisciplinarSchema = new mongoose.Schema({
  professor: String,
  email: String,
  data: String,
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
  status: { type: String, default: "Aguardando Confirmação" },
});

const userSchema = new mongoose.Schema({
  name: String,
  email: String,
  password: String,
  role: { type: String, default: "user" },
});

const Informatica = mongoose.model("Informatica", informaticaSchema);
const Multidisciplinar = mongoose.model(
  "Multidisciplinar",
  multidisciplinarSchema
);
const User = mongoose.model("User", userSchema);

// Open Route
app.get("/", (req, res) => {
  res.status(200).json({ message: "Bem vindo a api" });
});

// Middleware para checar o token
function checkToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) {
    return res.status(401).json({ message: "Acesso negado" });
  }

  try {
    const secret = process.env.SECRET;
    if (!secret) {
      throw new Error("Secret key not set");
    }
    jwt.verify(token, secret);
    next();
  } catch (error) {
    res.status(400).json({ message: "Token inválido!" });
  }
}

// Rota para obter todos os registros de informática
// app.get("/informatica", checkToken, async (req, res) => {
//   try {
//     const records = await Informatica.find();
//     res.status(200).json(records);
//   } catch (error) {
//     res
//       .status(500)
//       .json({ message: "Erro ao obter registros", error: error.message });
//   }
// });

// Rota para obter todos os registros de informática
app.get("/informatica", async (req, res) => {
  try {
    const records = await Informatica.find();
    res.status(200).json(records);
  } catch (error) {
    res
      .status(500)
      .json({ message: "Erro ao obter registros", error: error.message });
  }
});

// Rota para obter todos os registros multidisciplinares
app.get("/multidisciplinar", async (req, res) => {
  try {
    const records = await Multidisciplinar.find();
    res.status(200).json(records);
  } catch (error) {
    res
      .status(500)
      .json({ message: "Erro ao obter registros", error: error.message });
  }
});

// Rota para registrar um novo formulário de informática
app.post("/informatica/register", async (req, res) => {
  const {
    professor,
    email,
    data,
    modalidade,
    alunos,
    laboratorio,
    software,
    equipamento,
    observacao,
    token,
    userID,
  } = req.body;

  if (
    !professor ||
    !email ||
    !data ||
    !modalidade ||
    !alunos ||
    !laboratorio ||
    !software ||
    !equipamento ||
    !observacao ||
    !token
  ) {
    return res.status(400).json({ message: "Preencha todos os campos" });
  }

  try {
    const registrosNoDia = await Informatica.countDocuments({ data });
    if (registrosNoDia >= 5) {
      return res
        .status(400)
        .json({ message: "Laboratório Esgotado para esse dia" });
    }

    const laboratorioExistente = await Informatica.findOne({
      data,
      laboratorio,
    });
    if (laboratorioExistente) {
      return res.status(400).json({
        message: "Laboratório já possui uma solicitação para esse dia",
      });
    }

    const informatica = new Informatica({
      professor,
      email,
      data,
      modalidade,
      alunos,
      laboratorio,
      software,
      equipamento,
      observacao,
      token,
      userID,
    });

    await informatica.save();
    res.status(201).json({ message: "Formulário registrado com sucesso" });
  } catch (error) {
    res.status(500).json({ message: "Erro ao registrar formulário" });
  }
});

// Rota para apagar uma reserva com base no token
app.delete("/informatica/delete/:token", async (req, res) => {
  const { token } = req.params; // Obtém o token da URL

  if (!token) {
    return res.status(400).json({ message: "Token é obrigatório" });
  }

  try {
    // Busca e remove a reserva com o token correspondente
    const deletedReserva = await Informatica.findOneAndDelete({ token });

    if (!deletedReserva) {
      return res.status(404).json({ message: "Reserva não encontrada" });
    }

    res.status(200).json({ message: "Reserva apagada com sucesso" });
  } catch (error) {
    res.status(500).json({ message: "Erro ao apagar reserva" });
  }
});

// Rota para apagar uma reserva com base no token
app.delete("/multidisciplinar/delete/:token", async (req, res) => {
  const { token } = req.params; // Obtém o token da URL

  if (!token) {
    return res.status(400).json({ message: "Token é obrigatório" });
  }

  try {
    // Busca e remove a reserva com o token correspondente
    const deletedReserva = await Multidisciplinar.findOneAndDelete({ token });

    if (!deletedReserva) {
      return res.status(404).json({ message: "Reserva não encontrada" });
    }

    res.status(200).json({ message: "Reserva apagada com sucesso" });
  } catch (error) {
    res.status(500).json({ message: "Erro ao apagar reserva" });
  }
});

// Email validation functions
const validDomains = ["kroton.com.br", "cogna.com.br"];

const isValidEmailFormat = (email) => {
  const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return re.test(email);
};

const isDomainValid = (domain) => {
  return new Promise((resolve, reject) => {
    dns.resolveMx(domain, (err, addresses) => {
      if (err || addresses.length === 0) {
        resolve(false);
      } else {
        resolve(true);
      }
    });
  });
};

app.post("/auth/register", async (req, res) => {
  const { name, email, password, confirmpassword, role } = req.body;

  if (!name || !email || !password) {
    return res.status(400).json({ message: "Preencha todos os campos" });
  }

  if (password !== confirmpassword) {
    return res.status(400).json({ message: "As senhas não conferem" });
  }

  if (!isValidEmailFormat(email)) {
    return res.status(400).json({ message: "Formato de email inválido" });
  }

  const emailDomain = email.split("@")[1];
  if (!validDomains.includes(emailDomain)) {
    return res.status(400).json({
      message:
        "Por favor, utilize um email institucional (@kroton.com.br ou @cogna.com.br)",
    });
  }

  const isDomainValidResult = await isDomainValid(emailDomain);
  if (!isDomainValidResult) {
    return res
      .status(400)
      .json({ message: "O domínio do email não possui registros válidos" });
  }

  const userExists = await User.findOne({ email });
  if (userExists) {
    return res.status(400).json({ message: "Email já cadastrado" });
  }

  const salt = await bcrypt.genSalt(12);
  const passwordHash = await bcrypt.hash(password, salt);

  const user = new User({
    name,
    email,
    password: passwordHash,
    role: role || "user",
  });

  try {
    await user.save();
    res.status(201).json({ message: "Usuário cadastrado com sucesso" });
  } catch (error) {
    res.status(500).json({ message: "Erro ao cadastrar" });
  }
});

app.post("/auth/login", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ message: "Preencha todos os campos" });
  }

  const user = await User.findOne({ email });
  if (!user) {
    return res.status(404).json({ message: "Usuário não encontrado!" });
  }

  const checkPassword = await bcrypt.compare(password, user.password);
  if (!checkPassword) {
    return res.status(422).json({ message: "Senha incorreta" });
  }

  try {
    const secret = process.env.SECRET;
    if (!secret) {
      return res.status(500).json({ message: "Secret key not set" });
    }
    const token = jwt.sign({ id: user._id }, secret);
    res
      .status(200)
      .json({ message: "Logado com sucesso", token, userId: user._id });
  } catch (error) {
    res.status(500).json({ message: "Erro ao logar" });
  }
});

app.get("/auth/:id", checkToken, async (req, res) => {
  const id = req.params.id;
  const user = await User.findById(id);

  if (!user) {
    return res.status(404).json({ message: "Usuário não encontrado" });
  }

  res.status(200).json({ user });
});

app.post("/multidisciplinar/register", async (req, res) => {
  const {
    professor,
    email,
    data,
    modalidade,
    alunos,
    laboratorio,
    curso,
    turno,
    semestre,
    disciplina,
    tema,
    roteiro,
    observacao,
    token,
    userID,
  } = req.body;

  if (
    !professor ||
    !email ||
    !data ||
    !modalidade ||
    !alunos ||
    !laboratorio ||
    !curso ||
    !turno ||
    !semestre ||
    !disciplina ||
    !tema ||
    !roteiro ||
    !observacao ||
    !token
  ) {
    return res.status(400).json({ message: "Preencha todos os campos" });
  }

  try {
    const formulario = new Multidisciplinar({
      professor,
      email,
      data,
      modalidade,
      alunos,
      laboratorio,
      curso,
      turno,
      semestre,
      disciplina,
      tema,
      roteiro,
      observacao,
      token,
      userID,
    });

    await formulario.save();
    res.status(201).json({ message: "Formulário registrado com sucesso" });
  } catch (error) {
    res.status(500).json({ message: "Erro ao registrar formulário" });
  }
});

app.get("/buscartoken/:id", checkToken, async (req, res) => {
  const { id } = req.params;
  try {
    const informaticaRecord = await Informatica.findOne({ token: id });
    if (informaticaRecord) {
      return res.status(200).json(informaticaRecord);
    }

    const multidisciplinarRecord = await Multidisciplinar.findOne({
      token: id,
    });
    if (multidisciplinarRecord) {
      return res.status(200).json(multidisciplinarRecord);
    }

    return res.status(404).json({ message: "Token não encontrado" });
  } catch (error) {
    console.error("Erro ao obter dados do token:", error);
    res
      .status(500)
      .json({ message: "Erro ao obter dados do token", error: error.message });
  }
});

app.get("/minhassolicitacoes/:email", checkToken, async (req, res) => {
  const { email } = req.params;

  try {
    const informaticaRecords = await Informatica.find({ email });

    const multidisciplinarRecords = await Multidisciplinar.find({ email });

    const todasSolicitacoes = {
      informatica: informaticaRecords,
      multidisciplinar: multidisciplinarRecords
    };

    res.status(200).json(todasSolicitacoes);
  } catch (error) {
    console.error("Erro ao obter solicitações do professor:", error);
    res.status(500).json({
      message: "Erro ao obter solicitações do professor",
      error: error.message
    });
  }
});


app.listen(80, () => {
  console.log("Servidor Ligado com sucesso.");
});
