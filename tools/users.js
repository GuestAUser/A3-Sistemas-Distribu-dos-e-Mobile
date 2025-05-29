/**
 * Create Test Users Script
 * Creates test users with properly hashed passwords
 * Run: node users.js
 */

const axios = require('axios');

const API_URL = process.env.API_URL || 'http://localhost:3000';

const users = [
  { nome: 'João Silva',    cpf: '12345678011', email: 'joao@test.com',   senha: 'senha123' },
  { nome: 'Maria Oliveira',cpf: '98765432022', email: 'maria@test.com',  senha: 'senha123' },
  { nome: 'Carlos Souza',  cpf: '65432198033', email: 'carlos@test.com', senha: 'senha123' },
  { nome: 'Ana Costa',     cpf: '11223344556', email: 'ana@test.com',    senha: 'senha123' },
  { nome: 'Pedro Almeida', cpf: '55664433221', email: 'pedro@test.com',  senha: 'senha123' },
];

async function seed() {
  console.log(`🌱 Creating test users at ${API_URL}/api/usuarios\n`);

  for (const u of users) {
    try {
      const { data } = await axios.post(`${API_URL}/api/usuarios`, u);
      console.log(`✅ Created: ${u.email} (ID: ${data.id})`);
    } catch (e) {
      if (e.response?.data?.message?.includes('já cadastrado')) {
        console.log(`⚠️  Skipped: ${u.email} (already exists)`);
      } else {
        console.error(`❌ Failed: ${u.email}`, e.response?.data?.message || e.message);
      }
    }
  }

  console.log('\n✨ Done! All users can login with password: senha123');
}

seed().catch(console.error);