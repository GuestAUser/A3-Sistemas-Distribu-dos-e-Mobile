const express = require('express');
const axios = require('axios');
const cors = require('cors');
const path = require('path');

const app = express();
const PORT = 3000;

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

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
