/******************************************************************************
 *  index.js  –  API Fitness • Express + SQLite
 *  Node 23 ready (driver @vscode/sqlite3)
 *  Enhanced with CEP history and auto-suggestions (CEP OPTION MIGHT BE REMOVED)
 *  Code: GuestAUser - Github
 *******************************************************************************/
require('dotenv').config();

const express = require('express');
const axios   = require('axios');
const cors    = require('cors');
const helmet  = require('helmet');
const morgan  = require('morgan');
const bcrypt  = require('bcryptjs');
const path    = require('path');
const Joi     = require('joi');
const winston = require('winston');
const { db }  = require('./db');

const app  = express();
const PORT = process.env.PORT || 3000;

/* ---------- Rate Limiting ---------- */
const rateLimit = new Map();
const rateLimiter = (req, res, next) => {
  const ip = req.ip;
  const now = Date.now();
  const windowMs = 60 * 1000; // 1 minute;
  const maxRequests = 30;
  
  if (!rateLimit.has(ip)) {
    rateLimit.set(ip, []);
  }
  
  const requests = rateLimit.get(ip).filter(time => now - time < windowMs);
  
  if (requests.length >= maxRequests) {
    return res.status(429).json({ 
      success: false, 
      message: 'Muitas requisições. Tente novamente em 1 minuto.' 
    });
  }
  
  requests.push(now);
  rateLimit.set(ip, requests);
  next();
};

/* ---------- Logs com Winston ---------- */
const logger = winston.createLogger({
  level : 'info',
  format: winston.format.combine(
    winston.format.timestamp({ format: 'HH:mm:ss' }),
    winston.format.colorize(),
    winston.format.printf(({ level, message, timestamp }) =>
      `[${timestamp}] ${level}: ${message}`
    )
  ),
  transports: [new winston.transports.Console()]
});

/* ---------- Middlewares globais ---------- */
app.use(cors({
  origin: process.env.ALLOWED_ORIGINS?.split(',') || ['http://localhost:3000', 'http://localhost:3001', 'http://127.0.0.1:3000', 'http://127.0.0.1:3001'],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-User-Id']
}));
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'", "https://unpkg.com"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://unpkg.com"],
      imgSrc: ["'self'", "data:", "https://*.tile.openstreetmap.org"],
      connectSrc: ["'self'", "https://nominatim.openstreetmap.org", "https://overpass-api.de"]
    }
  }
}));
app.use(morgan('dev'));
app.use(express.json({ limit: '10mb' }));
app.use(express.static(path.join(__dirname, 'public')));
app.use(rateLimiter);

/* ---------- Helpers ---------- */
const asyncH = fn => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

const schemaCadastro = Joi.object({
  nome : Joi.string().min(2).max(100).required(),
  cpf  : Joi.string().length(11).pattern(/^\d+$/).required(),
  email: Joi.string().email().max(255).required(),
  senha: Joi.string().min(6).max(72).required()
});

const schemaLogin = Joi.object({
  email: Joi.string().email().required(),
  senha: Joi.string().required()
});

const schemaCep = Joi.string().length(8).pattern(/^\d+$/);

const schemaParques = Joi.object({
  cep: Joi.string().length(8).pattern(/^\d+$/).required(),
  raio: Joi.number().min(500).max(10000).default(3000)
});

/* ---------- Migração ---------- */
db.serialize(() => {
  // Users table;
  db.run(`
    CREATE TABLE IF NOT EXISTS usuarios (
      id     INTEGER PRIMARY KEY AUTOINCREMENT,
      nome   TEXT NOT NULL,
      cpf    TEXT NOT NULL UNIQUE,
      email  TEXT NOT NULL UNIQUE,
      senha  TEXT NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  // CEP history table; (Deprecated systems for the api connection, switching for google in next update).
  db.run(`
    CREATE TABLE IF NOT EXISTS user_ceps (
      id          INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id     INTEGER NOT NULL,
      cep         TEXT NOT NULL,
      search_count INTEGER DEFAULT 1,
      last_searched DATETIME DEFAULT CURRENT_TIMESTAMP,
      created_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES usuarios(id) ON DELETE CASCADE,
      UNIQUE(user_id, cep)
    )
  `);

  // Create index's. [ For better performance ];
  db.run(`CREATE INDEX IF NOT EXISTS idx_user_ceps_user_id ON user_ceps(user_id)`);
  db.run(`CREATE INDEX IF NOT EXISTS idx_user_ceps_last_searched ON user_ceps(last_searched DESC)`);
  
  logger.info('📊 Database migrations completed');
});

/* ==========================================================
 *  ROTAS
 * ======================================================== */

/* Health-check */
app.get('/api/saude', (_req, res) => res.json({ 
  ok: true, 
  ts: Date.now(),
  version: '2.45.3',
  node: process.version
}));

/* Cadastro */
app.post('/api/usuarios', asyncH(async (req, res) => {
  const { error } = schemaCadastro.validate(req.body);
  if (error) return res.status(400).json({ success: false, message: error.message });

  const { nome, cpf, email, senha } = req.body;
  const hash = await bcrypt.hash(senha, 10);

  db.run(
    'INSERT INTO usuarios (nome, cpf, email, senha) VALUES (?, ?, ?, ?)',
    [nome, cpf, email, hash],
    function (err) {
      if (err) {
        const dup = err.message.includes('UNIQUE');
        return res.status(409).json({
          success: false,
          message: dup ? 'CPF ou e-mail já cadastrado' : 'Erro ao criar usuário'
        });
      }
      res.status(201).json({ success: true, id: this.lastID });
      logger.info(`Novo usuário #${this.lastID} (${email})`);
    }
  );
}));

/* Login with CEP history */
app.post('/api/auth/login', asyncH(async (req, res) => {
  const { error } = schemaLogin.validate(req.body);
  if (error) return res.status(400).json({ success: false, message: error.message });

  const { email, senha } = req.body;

  db.get('SELECT * FROM usuarios WHERE email = ?', [email], async (err, u) => {
    if (err) return res.status(500).json({ success: false, message: 'Erro de leitura' });
    if (!u) return res.status(401).json({ success: false, message: 'Usuário não encontrado' });

    const ok = await bcrypt.compare(senha, u.senha);
    if (!ok) return res.status(401).json({ success: false, message: 'Senha incorreta' });

    // Get user's recent CEPs
    db.all(
      `SELECT cep, search_count, last_searched 
       FROM user_ceps 
       WHERE user_id = ? 
       ORDER BY search_count DESC, last_searched DESC 
       LIMIT 5`,
      [u.id],
      (err, ceps) => {
        if (err) {
          logger.error('Erro ao buscar CEPs:', err);
          ceps = [];
        }

        res.json({ 
          success: true, 
          user: {
            id: u.id,
            nome: u.nome,
            email: u.email
          },
          recentCeps: ceps || []
        });
        logger.info(`Login de ${email}`);
      }
    );
  });
}));

/* CEP → Coordenadas (via ViaCEP + Nominatim) */
app.get('/api/geo/cep/:cep', asyncH(async (req, res) => {
  const rawCep = req.params.cep;
  const cleanedCep = rawCep.replace(/\D/g, '');
  
  const { error } = schemaCep.validate(cleanedCep);
  if (error) return res.status(400).json({ success: false, message: 'CEP inválido' });

  try {
    logger.info(`Buscando CEP ${cleanedCep} no ViaCEP`);
    const viaCepUrl = `https://viacep.com.br/ws/${cleanedCep}/json/`;
    const viaCepResponse = await axios.get(viaCepUrl, { timeout: 5000 });
    
    if (viaCepResponse.data.erro) {
      logger.warn(`CEP ${cleanedCep} não encontrado no ViaCEP`);
      return res.status(404).json({ success: false, message: 'CEP não encontrado' });
    }
    
    const { logradouro, bairro, localidade, uf } = viaCepResponse.data;
    
    logger.info(`CEP ${cleanedCep}: ${localidade}/${uf}`);
    
    const searchAddress = [logradouro, bairro, localidade, uf, 'Brazil']
      .filter(part => part && part.trim())
      .join(', ');
    
    const searchQuery = encodeURIComponent(searchAddress);

    let nominatimUrl = `https://nominatim.openstreetmap.org/search?q=${searchQuery}&format=json&limit=1&countrycodes=br`;
    
    logger.info(`Geocoding: ${decodeURIComponent(searchQuery)}`);
    
    let nominatimResponse = await axios.get(nominatimUrl, {
      headers: { 'User-Agent': 'ProjetoFitness/2.45.3 (UniBH)' },
      timeout: 5000
    });
    
    if (!nominatimResponse.data.length && bairro) {
      const neighborhoodQuery = encodeURIComponent(`${bairro}, ${localidade}, ${uf}, Brazil`);
      nominatimUrl = `https://nominatim.openstreetmap.org/search?q=${neighborhoodQuery}&format=json&limit=1&countrycodes=br`;
      
      logger.info(`Trying neighborhood search: ${decodeURIComponent(neighborhoodQuery)}`);
      
      nominatimResponse = await axios.get(nominatimUrl, {
        headers: { 'User-Agent': 'ProjetoFitness/2.45.3 (UniBH)' },
        timeout: 5000
      });
    }

    if (!nominatimResponse.data.length) {
      const cityQuery = encodeURIComponent(`${localidade}, ${uf}, Brazil`);
      nominatimUrl = `https://nominatim.openstreetmap.org/search?q=${cityQuery}&format=json&limit=1&countrycodes=br`;
      
      logger.info(`Fallback to city search: ${decodeURIComponent(cityQuery)}`);
      
      nominatimResponse = await axios.get(nominatimUrl, {
        headers: { 'User-Agent': 'ProjetoFitness/2.45.3 (UniBH)' },
        timeout: 5000
      });
    }
    
    if (!nominatimResponse.data.length) {
      // { Major fallback: direct cords }
      const cityCoords = {
        'Belo Horizonte': { lat: -19.9245, lon: -43.9352 },
        'São Paulo': { lat: -23.5505, lon: -46.6333 },
        'Rio de Janeiro': { lat: -22.9068, lon: -43.1729 },
        'Brasília': { lat: -15.7801, lon: -47.9292 },
        'Salvador': { lat: -12.9777, lon: -38.5016 },
        'Fortaleza': { lat: -3.7327, lon: -38.5270 },
        'Curitiba': { lat: -25.4284, lon: -49.2733 },
        'Recife': { lat: -8.0476, lon: -34.8770 },
        'Porto Alegre': { lat: -30.0346, lon: -51.2177 },
        'Manaus': { lat: -3.1190, lon: -60.0217 },
        'Belém': { lat: -1.4558, lon: -48.4902 },
        'Goiânia': { lat: -16.6864, lon: -49.2643 },
        'Guarulhos': { lat: -23.4538, lon: -46.5333 },
        'Campinas': { lat: -22.9099, lon: -47.0626 },
        'Nova Iguaçu': { lat: -22.7556, lon: -43.4440 },
        'Maceió': { lat: -9.6662, lon: -35.7356 },
        'São Luís': { lat: -2.5307, lon: -44.3068 },
        'Natal': { lat: -5.7945, lon: -35.2110 },
        'Campo Grande': { lat: -20.4697, lon: -54.6201 },
        'Teresina': { lat: -5.0892, lon: -42.8019 },
        'João Pessoa': { lat: -7.1195, lon: -34.8450 },
        'Aracaju': { lat: -10.9472, lon: -37.0731 },
        'Contagem': { lat: -19.9386, lon: -44.0539 },
        'Uberlândia': { lat: -18.9186, lon: -48.2772 },
        'Nova Lima': { lat: -19.9868, lon: -43.8466 }
      };
      
      const coords = cityCoords[localidade];
      if (coords) {
        logger.info(`Usando coordenadas aproximadas para ${localidade}`);
        const approximateAddress = `${localidade} - ${uf}`;
        
        return res.json({
          success: true,
          lat: coords.lat,
          lon: coords.lon,
          endereco: approximateAddress,
          aproximado: true
        });
      }
      
      return res.status(404).json({ 
        success: false, 
        message: 'Não foi possível determinar as coordenadas deste CEP' 
      });
    }
    
    const { lat, lon } = nominatimResponse.data[0];
    
    const formattedAddress = [logradouro, bairro, localidade, uf]
      .filter(part => part && part.trim())
      .join(', ');
    
    logger.info(`Coordenadas encontradas para CEP ${cleanedCep}: ${lat}, ${lon}`);
    
    res.json({ 
      success: true, 
      lat: Number(lat), 
      lon: Number(lon), 
      endereco: searchAddress
    });
    
  } catch (error) {
    logger.error('Erro ao buscar CEP:', error.message, error.response?.data);
    
    // If ViaCEP is down.
    if (error.code === 'ECONNABORTED') {
      return res.status(503).json({ 
        success: false, 
        message: 'Serviço de CEP temporariamente indisponível. Tente novamente.' 
      });
    }
    
    if (error.response?.status === 404) {
      return res.status(404).json({ success: false, message: 'CEP não encontrado' });
    }
    
    res.status(503).json({ 
      success: false, 
      message: 'Serviço de geolocalização temporariamente indisponível' 
    });
  }
}));

/* Parques próximos - CEP only with history tracking */
app.get('/api/parques', asyncH(async (req, res) => {
  if (req.query.cep) {
    req.query.cep = req.query.cep.replace(/\D/g, '');
  }
  
  const { error, value } = schemaParques.validate(req.query);
  if (error) return res.status(400).json({ success: false, message: error.message });

  const { cep, raio } = value;
  const userId = req.headers['x-user-id'];

  try {
    const geoResponse = await axios.get(`http://localhost:${PORT}/api/geo/cep/${cep}`);
    const { lat, lon } = geoResponse.data;

    if (userId && !isNaN(parseInt(userId))) {
      db.run(
        `INSERT INTO user_ceps (user_id, cep, search_count, last_searched)
         VALUES (?, ?, 1, CURRENT_TIMESTAMP)
         ON CONFLICT(user_id, cep) DO UPDATE SET
           search_count = search_count + 1,
           last_searched = CURRENT_TIMESTAMP`,
        [parseInt(userId), cep],
        (err) => {
          if (err) logger.error('Erro ao salvar CEP:', err);
        }
      );
    }

    // Query parks from (Overpass API).
    const q = `
      [out:json][timeout:25];
      (
        node["leisure"~"^(park|garden|playground|nature_reserve)$"](around:${raio},${lat},${lon});
        way["leisure"~"^(park|garden|playground|nature_reserve)$"](around:${raio},${lat},${lon});
        relation["leisure"~"^(park|garden|playground|nature_reserve)$"](around:${raio},${lat},${lon});
        node["tourism"="park"](around:${raio},${lat},${lon});
        way["tourism"="park"](around:${raio},${lat},${lon});
      );
      out center;`;

    const { data } = await axios.post(
      'https://overpass-api.de/api/interpreter',
      `data=${encodeURIComponent(q)}`,
      { 
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        timeout: 10000
      }
    );
    
    logger.info(`Overpass API retornou ${data.elements.length} elementos`);

    // Filter and map parks with better error handling.
    const parques = data.elements
      .filter(e => {
        if (!e.tags?.name || e.tags.name === 'Parque sem nome') return false;

        const lat = e.lat || e.center?.lat;
        const lon = e.lon || e.center?.lon;
        return lat && lon;
      })
      .map(e => ({
        id: e.id,
        nome: e.tags.name,
        latitude: e.lat || e.center?.lat,
        longitude: e.lon || e.center?.lon,
        descricao: e.tags.description || e.tags['description:pt'] || null,
        abertura: e.tags.opening_hours || null,
        tipo: e.tags.leisure || e.tags.tourism || 'park',
        website: e.tags.website || null
      }));

    logger.info(`Encontrados ${parques.length} parques próximos ao CEP ${cep}`);

    res.json({ 
      success: true, 
      parques,
      centro: { lat, lon },
      endereco: geoResponse.data.endereco,
      aproximado: geoResponse.data.aproximado || false,
      cep,
      raio
    });
    
  } catch (error) {
    if (error.response?.status === 404) {
      return res.status(404).json({ success: false, message: 'CEP não encontrado' });
    }
    logger.error('Erro ao buscar parques:', error.message);
    res.status(500).json({ success: false, message: 'Erro ao buscar parques' });
  }
}));

/* Get user's CEP history */
app.get('/api/usuarios/:userId/ceps', asyncH(async (req, res) => {
  const userId = parseInt(req.params.userId);
  if (isNaN(userId)) {
    return res.status(400).json({ success: false, message: 'ID de usuário inválido' });
  }

  db.all(
    `SELECT cep, search_count, last_searched 
     FROM user_ceps 
     WHERE user_id = ? 
     ORDER BY search_count DESC, last_searched DESC 
     LIMIT 10`,
    [userId],
    (err, ceps) => {
      if (err) {
        logger.error('Erro ao buscar histórico de CEPs:', err);
        return res.status(500).json({ success: false, message: 'Erro ao buscar histórico' });
      }
      res.json({ success: true, ceps: ceps || [] });
    }
  );
}));

/* Clear user's CEP history */
app.delete('/api/usuarios/:userId/ceps', asyncH(async (req, res) => {
  const userId = parseInt(req.params.userId);
  if (isNaN(userId)) {
    return res.status(400).json({ success: false, message: 'ID de usuário inválido' });
  }

  db.run('DELETE FROM user_ceps WHERE user_id = ?', [userId], function(err) {
    if (err) {
      logger.error('Erro ao limpar histórico:', err);
      return res.status(500).json({ success: false, message: 'Erro ao limpar histórico' });
    }
    res.json({ success: true, deleted: this.changes });
  });
}));

/* 404 */
app.use((_req, res) => res.status(404).json({ success: false, message: 'Rota não encontrada' }));

/* Handler global */
app.use((err, _req, res, _next) => {
  logger.error(err.stack || err);
  res.status(500).json({ success: false, message: 'Erro interno do servidor' });
});

/* Start */
app.listen(PORT, () => logger.info(`🚀  API Fitness rodando em http://localhost:${PORT}`));