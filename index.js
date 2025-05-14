const express = require('express');
const axios = require('axios');
const cors = require('cors');
const path = require('path');
const bcrypt = require('bcryptjs');
const { db } = require('./db');

const app = express();
const PORT = 3000;

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Criação da tabela com CPF
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS Usuarios (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    nome TEXT NOT NULL,
    cpf TEXT NOT NULL UNIQUE,
    email TEXT NOT NULL UNIQUE,
    senha TEXT NOT NULL
  )`);
});

// Cadastro com CPF
app.post('/criar-usuario', async (req, res) => {
  const { nome, cpf, email, senha } = req.body;

  if (!nome || !cpf || !email || !senha) {
    return res.status(400).json({ success: false, message: 'Todos os campos são obrigatórios.' });
  }

  try {
    const salt = await bcrypt.genSalt(10);
    const senhaCriptografada = await bcrypt.hash(senha, salt);

    db.run(
      `INSERT INTO Usuarios (nome, cpf, email, senha) VALUES (?, ?, ?, ?)`,
      [nome, cpf, email, senhaCriptografada],
      function (err) {
        if (err) {
          console.error(err.message);
          return res.status(500).json({
            success: false,
            message: 'Erro ao criar usuário. Verifique se o CPF ou Email já está cadastrado.'
          });
        }

        res.json({ success: true, message: 'Usuário criado com sucesso!' });
      }
    );
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Erro ao criar usuário.' });
  }
});

// Login (sem CPF)
app.post('/login', (req, res) => {
  const { email, senha } = req.body;

  if (!email || !senha) {
    return res.status(400).json({ success: false, message: 'Email e senha são obrigatórios.' });
  }

  db.get(`SELECT * FROM Usuarios WHERE email = ?`, [email], async (err, usuario) => {
    if (err) {
      console.error(err.message);
      return res.status(500).json({ success: false, message: 'Erro ao buscar usuário.' });
    }

    if (!usuario) {
      return res.status(401).json({ success: false, message: 'Usuário não encontrado.' });
    }

    const senhaValida = await bcrypt.compare(senha, usuario.senha);

    if (!senhaValida) {
      return res.status(401).json({ success: false, message: 'Senha incorreta.' });
    }

    res.json({ success: true, message: 'Login realizado com sucesso!', nome: usuario.nome });
  });
});

// Busca de parques próximos
app.post('/parques-proximos', async (req, res) => {
  const { latitude, longitude } = req.body;

  if (!latitude || !longitude) {
    return res.status(400).json({ error: 'Latitude e longitude são obrigatórios.' });
  }

  const overpassQuery = `
    [out:json];
    (
      node["leisure"="park"](around:3000,${latitude},${longitude});
      way["leisure"="park"](around:3000,${latitude},${longitude});
      relation["leisure"="park"](around:3000,${latitude},${longitude});
    );
    out center;
  `;

  try {
    const response = await axios.post(
      'https://overpass-api.de/api/interpreter',
      `data=${encodeURIComponent(overpassQuery)}`,
      {
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded'
        }
      }
    );

    const parques = response.data.elements.map((e) => {
      const nome = e.tags?.name || 'Parque sem nome';
      const lat = e.lat || e.center?.lat;
      const lon = e.lon || e.center?.lon;

      return { nome, latitude: lat, longitude: lon };
    });

    res.json({ parques });
  } catch (err) {
    console.error(err.message);
    res.status(500).json({ error: 'Erro ao buscar parques.' });
  }
});

app.listen(PORT, () => {
  console.log(`Servidor rodando em http://localhost:${PORT}`);
});
