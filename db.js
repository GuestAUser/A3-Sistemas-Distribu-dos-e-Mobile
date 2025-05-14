const sqlite3 = require('sqlite3').verbose();
const path = require('path');

// Caminho para o banco de dados (arquivo local)
const dbPath = path.resolve(__dirname, 'database.sqlite');

// Conexão com o banco de dados
const db = new sqlite3.Database(dbPath, (err) => {
  if (err) {
    console.error('Erro ao conectar ao banco de dados SQLite:', err.message);
  } else {
    console.log('Conectado ao banco de dados SQLite com sucesso.');
  }
});

module.exports = { db };
