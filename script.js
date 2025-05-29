let currentUser = null;
let accessToken = null;
let refreshToken = null;
let map = null;
let searchCircle = null;
let parkMarkers = [];
let centerMarker = null;

const loginForm = document.getElementById('loginForm');
const loginMsg = document.getElementById('loginMsg');
const parkForm = document.getElementById('parkForm');
const parkList = document.getElementById('parkList');
const parkCount = document.getElementById('parkCount');
const searchLocation = document.getElementById('searchLocation');
const authSection = document.getElementById('auth');
const parksSec = document.getElementById('parks');
const raioSlider = document.getElementById('raioSlider');
const raioValue = document.getElementById('raioValue');
const themeToggle = document.getElementById('themeToggle');
const loadingOverlay = document.getElementById('loadingOverlay');
const userMenuBtn = document.getElementById('userMenuBtn');
const userMenu = document.getElementById('userMenu');
const logoutBtn = document.getElementById('logoutBtn');
const clearHistory = document.getElementById('clearHistory');
const recentCeps = document.getElementById('recentCeps');
const cepChips = document.getElementById('cepChips');
const cepInput = document.querySelector('input[name="cep"]');
const cepHelper = document.getElementById('cepHelper');

function initParticles() {
  const particlesContainer = document.getElementById('particles');
  const particleCount = 50;

  for (let i = 0; i < particleCount; i++) {
    const particle = document.createElement('div');
    particle.className = 'particle';
    particle.style.left = Math.random() * 100 + '%';
    particle.style.animationDelay = Math.random() * 20 + 's';
    particle.style.animationDuration = (Math.random() * 20 + 10) + 's';
    particlesContainer.appendChild(particle);
  }
}

function setLoading(show) {
  loadingOverlay.style.display = show ? 'flex' : 'none';
}

function showMessage(element, text, type = 'info') {
  element.textContent = text;
  element.className = `message ${type}`;
  element.style.animation = 'slideIn 0.3s ease-out';
}

async function apiRequest(url, options = {}) {
  const headers = {
    'Content-Type': 'application/json',
    ...options.headers
  };

  if (accessToken) {
    headers['Authorization'] = `Bearer ${accessToken}`;
  }

  const response = await fetch(url, {
    ...options,
    headers
  });

  if (response.status === 401 && refreshToken) {
    const data = await response.json();
    if (data.code === 'TOKEN_EXPIRED') {
      const refreshed = await refreshAccessToken();
      if (refreshed) {

        headers['Authorization'] = `Bearer ${accessToken}`;
        return fetch(url, { ...options, headers });
      }
    }
  }

  return response;
}

async function refreshAccessToken() {
  try {
    const response = await fetch('/api/auth/refresh', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ refreshToken })
    });

    const data = await response.json();
    if (data.success) {
      accessToken = data.accessToken;
      refreshToken = data.refreshToken;
      return true;
    }
  } catch (error) {
    console.error('Failed to refresh token:', error);
  }

  accessToken = null;
  refreshToken = null;
  currentUser = null;
  location.reload();
  return false;
}

function initMap() {
  map = L.map('map', {
    zoomControl: false,
    attributionControl: true
  }).setView([-19.9245, -43.9352], 13);

  L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
    attribution: '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a>',
    className: 'map-tiles'
  }).addTo(map);

  document.getElementById('zoomIn').addEventListener('click', () => {
    map.zoomIn();
  });

  document.getElementById('zoomOut').addEventListener('click', () => {
    map.zoomOut();
  });

  document.getElementById('centerMap').addEventListener('click', () => {
    if (centerMarker) {
      map.setView(centerMarker.getLatLng(), 14);
      centerMarker.openPopup();
    }
  });

  setTimeout(() => {
    map.invalidateSize();
  }, 300);
}

function formatCEP(cep) {
  const cleaned = cep.toString().replace(/\D/g, '');
  if (cleaned.length !== 8) return cep;
  return cleaned.replace(/(\d{5})(\d{3})/, '$1-$2');
}

function cleanCEP(cep) {
  return cep.toString().replace(/\D/g, '').substring(0, 8);
}

function createParkIcon() {
  return L.divIcon({
    html: `<div class="park-marker-icon">
            <span>🌳</span>
          </div>`,
    className: 'park-marker',
    iconSize: [40, 40],
    iconAnchor: [20, 20],
    popupAnchor: [0, -20]
  });
}

function createCenterIcon() {
  return L.divIcon({
    html: `<div class="center-marker-icon">
            <span>📍</span>
          </div>`,
    className: 'center-marker',
    iconSize: [40, 40],
    iconAnchor: [20, 40],
    popupAnchor: [0, -40]
  });
}

loginForm.addEventListener('submit', async (e) => {
  e.preventDefault();

  const submitBtn = loginForm.querySelector('button[type="submit"]');
  const btnText = submitBtn.querySelector('.btn-text');
  const btnLoader = submitBtn.querySelector('.btn-loader');

  btnText.style.display = 'none';
  btnLoader.hidden = false;
  submitBtn.disabled = true;

  const formData = Object.fromEntries(new FormData(loginForm));

  try {
    const response = await fetch('/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(formData)
    });

    const data = await response.json();

    if (data.success) {

      currentUser = data.user;
      accessToken = data.accessToken;
      refreshToken = data.refreshToken;

      showMessage(loginMsg, `Bem-vindo, ${data.user.nome}!`, 'success');

      setTimeout(() => {
        authSection.hidden = true;
        parksSec.hidden = false;

        userMenuBtn.hidden = false;
        userMenuBtn.querySelector('.user-name').textContent = data.user.nome;
        document.querySelector('.user-menu-name').textContent = data.user.nome;
        document.querySelector('.user-menu-email').textContent = data.user.email;

        initMap();

        if (data.recentCeps && data.recentCeps.length > 0) {
          displayRecentCeps(data.recentCeps);

          const mostRecent = data.recentCeps[0];
          cepInput.value = cleanCEP(mostRecent.cep);

          setTimeout(() => {
            parkForm.dispatchEvent(new Event('submit'));
          }, 500);
        }
      }, 1000);
    } else {
      showMessage(loginMsg, data.message || 'Credenciais inválidas', 'error');
    }
  } catch (error) {
    showMessage(loginMsg, 'Erro ao conectar ao servidor', 'error');
    console.error(error);
  } finally {
    btnText.style.display = 'inline';
    btnLoader.hidden = true;
    submitBtn.disabled = false;
  }
});

function displayRecentCeps(ceps) {
  if (ceps.length === 0) {
    recentCeps.hidden = true;
    return;
  }

  recentCeps.hidden = false;
  cepChips.innerHTML = ceps.map(cep => `
    <button class="cep-chip" data-cep="${cep.cep}" title="Pesquisado ${cep.search_count}x">
      <span class="cep-chip-text">${formatCEP(cep.cep)}</span>
      <span class="cep-chip-count">${cep.search_count}</span>
    </button>
  `).join('');

  document.querySelectorAll('.cep-chip').forEach(chip => {
    chip.addEventListener('click', () => {
      const cleanedCep = cleanCEP(chip.dataset.cep);
      cepInput.value = cleanedCep;

      cepInput.classList.add('pulse');
      setTimeout(() => cepInput.classList.remove('pulse'), 600);
    });
  });
}

parkForm.addEventListener('submit', async (e) => {
  e.preventDefault();

  const submitBtn = parkForm.querySelector('button[type="submit"]');
  const btnText = submitBtn.querySelector('.btn-text');
  const btnLoader = submitBtn.querySelector('.btn-loader');

  btnText.style.display = 'none';
  btnLoader.hidden = false;
  submitBtn.disabled = true;

  parkList.innerHTML = '<li class="loading-item">🔄 Buscando parques próximos...</li>';

  try {
    const formData = Object.fromEntries(new FormData(parkForm));
    formData.cep = cleanCEP(formData.cep);

    const params = new URLSearchParams(formData);

    const response = await apiRequest('/api/parques?' + params);
    const data = await response.json();

    console.log('Resposta da busca:', data);

    if (!data.success) {
      let errorMessage = data.message;
      if (data.message === 'CEP não encontrado') {
        errorMessage = '❌ CEP não encontrado. Verifique se o CEP está correto.';
      } else if (data.message === 'Não foi possível determinar as coordenadas deste CEP') {
        errorMessage = '❌ Não conseguimos localizar este CEP no mapa. Tente um CEP próximo.';
      } else if (data.code === 'NO_TOKEN') {
        errorMessage = '❌ Sessão expirada. Faça login novamente.';
        setTimeout(() => location.reload(), 2000);
      }

      parkList.innerHTML = `<li class="error-item">${errorMessage}</li>`;
      parkCount.textContent = 'Erro na busca';
      searchLocation.textContent = '';
      return;
    }

    const addressText = data.endereco ? 
      `📍 ${data.endereco}<br><small>CEP ${formatCEP(data.cep)} • Raio: ${data.raio / 1000}km</small>` :
      `📍 CEP ${formatCEP(data.cep)} • Raio: ${data.raio / 1000}km`;
    searchLocation.innerHTML = addressText;

    parkMarkers.forEach(marker => map.removeLayer(marker));
    parkMarkers = [];

    if (searchCircle) {
      map.removeLayer(searchCircle);
    }

    if (centerMarker) {
      map.removeLayer(centerMarker);
    }

    centerMarker = L.marker([data.centro.lat, data.centro.lon], { 
      icon: createCenterIcon(),
      zIndexOffset: 1000
    })
      .addTo(map)
      .bindPopup(`<strong>Centro da busca</strong><br>${data.endereco || 'CEP: ' + formatCEP(data.cep)}`);

    searchCircle = L.circle([data.centro.lat, data.centro.lon], {
      radius: data.raio,
      color: '#22d3ee',
      fillColor: '#22d3ee',
      fillOpacity: 0.1,
      weight: 2,
      className: 'search-circle'
    }).addTo(map);

    const parksWithDistance = data.parques.map(park => {
      const distance = calculateDistance(
        data.centro.lat, data.centro.lon,
        park.latitude, park.longitude
      );
      return { ...park, distance };
    }).sort((a, b) => a.distance - b.distance);

    parkCount.textContent = `${parksWithDistance.length} parques encontrados`;

    if (data.aproximado) {
      parkCount.innerHTML += '<br><small style="color: var(--warning)">⚠️ Usando coordenadas aproximadas da cidade</small>';
    }

    if (parksWithDistance.length > 0) {
      parkList.innerHTML = parksWithDistance.map((park, index) => {
        const typeLabel = park.tipo === 'garden' ? '🌻 Jardim' : 
                         park.tipo === 'playground' ? '🎮 Playground' :
                         park.tipo === 'nature_reserve' ? '🌲 Reserva' : '🌳 Parque';

        return `
        <li class="park-item" data-index="${index}">
          <div class="park-item-content">
            <div class="park-item-icon">${typeLabel.split(' ')[0]}</div>
            <div class="park-item-info">
              <div class="park-name">${park.nome}</div>
              <div class="park-details">
                <span class="park-distance">📏 ${formatDistance(park.distance)}</span>
                ${park.tipo !== 'park' ? `<span class="park-type">${typeLabel}</span>` : ''}
                ${park.abertura ? `<span class="park-hours">🕐 ${park.abertura}</span>` : ''}
              </div>
            </div>
          </div>
        </li>
      `}).join('');

      parksWithDistance.forEach((park, index) => {
        setTimeout(() => {
          const typeLabel = park.tipo === 'garden' ? 'Jardim' : 
                           park.tipo === 'playground' ? 'Playground' :
                           park.tipo === 'nature_reserve' ? 'Reserva Natural' : 'Parque';

          const marker = L.marker([park.latitude, park.longitude], { 
            icon: createParkIcon()
          })
            .addTo(map)
            .bindPopup(`
              <div class="park-popup">
                <h3>${park.nome}</h3>
                <p><em>${typeLabel}</em></p>
                <p>📏 Distância: ${formatDistance(park.distance)}</p>
                ${park.descricao ? `<p>${park.descricao}</p>` : ''}
                ${park.abertura ? `<p>🕐 ${park.abertura}</p>` : ''}
                ${park.website ? `<p><a href="${park.website}" target="_blank">🌐 Website</a></p>` : ''}
              </div>
            `);

          parkMarkers.push(marker);

          marker._icon.classList.add('marker-drop');
        }, index * 50);
      });

      document.querySelectorAll('.park-item').forEach(item => {
        item.addEventListener('click', () => {
          const index = parseInt(item.dataset.index);
          const park = parksWithDistance[index];

          document.querySelectorAll('.park-item').forEach(i => i.classList.remove('selected'));
          item.classList.add('selected');

          map.setView([park.latitude, park.longitude], 16);
          parkMarkers[index].openPopup();
        });
      });

      setTimeout(() => {
        const bounds = L.latLngBounds([centerMarker.getLatLng()]);
        parkMarkers.forEach(marker => bounds.extend(marker.getLatLng()));
        map.fitBounds(bounds.pad(0.1));
      }, parksWithDistance.length * 50 + 200);

    } else {
      parkList.innerHTML = '<li class="empty-item">😔 Nenhum parque encontrado neste raio</li>';
    }

    if (currentUser) {
      updateRecentCeps();
    }

  } catch (error) {
    parkList.innerHTML = '<li class="error-item">❌ Erro ao buscar parques</li>';
    parkCount.textContent = 'Erro na busca';
    console.error(error);
  } finally {
    btnText.style.display = 'inline';
    btnLoader.hidden = true;
    submitBtn.disabled = false;
  }
});

async function updateRecentCeps() {
  if (!currentUser) return;

  try {
    const response = await apiRequest(`/api/usuarios/${currentUser.id}/ceps`);
    const data = await response.json();

    if (data.success) {
      displayRecentCeps(data.ceps);
    }
  } catch (error) {
    console.error('Erro ao atualizar CEPs recentes:', error);
  }
}

clearHistory.addEventListener('click', async () => {
  if (!currentUser) return;

  if (!confirm('Deseja limpar todo o histórico de CEPs?')) return;

  try {
    const response = await apiRequest(`/api/usuarios/${currentUser.id}/ceps`, {
      method: 'DELETE'
    });

    const data = await response.json();

    if (data.success) {
      displayRecentCeps([]);
      showMessage(parkCount, 'Histórico limpo com sucesso', 'success');
    }
  } catch (error) {
    console.error('Erro ao limpar histórico:', error);
  }
});

raioSlider.addEventListener('input', () => {
  const km = raioSlider.value / 1000;
  raioValue.textContent = km % 1 === 0 ? `${km}km` : `${km.toFixed(1)}km`;

  if (searchCircle) {
    searchCircle.setRadius(parseInt(raioSlider.value));
  }
});

cepInput.addEventListener('paste', (e) => {
  e.preventDefault();
  const pastedText = (e.clipboardData || window.clipboardData).getData('text');
  const cleanedCEP = pastedText.replace(/\D/g, '');

  if (pastedText !== cleanedCEP && cleanedCEP.length >= 8) {
    cepHelper.hidden = false;
    cepHelper.style.animation = 'none';
    setTimeout(() => {
      cepHelper.style.animation = 'fadeInOut 2s ease-out';
      setTimeout(() => { cepHelper.hidden = true; }, 2000);
    }, 10);
  }

  cepInput.classList.add('formatting');
  setTimeout(() => cepInput.classList.remove('formatting'), 300);

  if (cleanedCEP.length >= 8) {
    e.target.value = cleanedCEP.substring(0, 8);
  } else {
    e.target.value = cleanedCEP;
  }

  e.target.dispatchEvent(new Event('input', { bubbles: true }));
});

cepInput.addEventListener('input', (e) => {
  const cleaned = e.target.value.replace(/\D/g, '');

  if (e.target.value !== cleaned) {
    const cursorPos = e.target.selectionStart;
    e.target.value = cleaned.substring(0, 8);

    cepHelper.hidden = false;
    cepHelper.style.animation = 'none';
    setTimeout(() => {
      cepHelper.style.animation = 'fadeInOut 2s ease-out';
      setTimeout(() => { cepHelper.hidden = true; }, 2000);
    }, 10);

    cepInput.classList.add('formatting');
    setTimeout(() => cepInput.classList.remove('formatting'), 300);

    const newPos = Math.min(cursorPos, e.target.value.length);
    e.target.setSelectionRange(newPos, newPos);
  }
});

function calculateDistance(lat1, lon1, lat2, lon2) {
  const R = 6371;
  const dLat = deg2rad(lat2 - lat1);
  const dLon = deg2rad(lon2 - lon1);
  const a = 
    Math.sin(dLat/2) * Math.sin(dLat/2) +
    Math.cos(deg2rad(lat1)) * Math.cos(deg2rad(lat2)) * 
    Math.sin(dLon/2) * Math.sin(dLon/2);
  const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1-a));
  return R * c;
}

function deg2rad(deg) {
  return deg * (Math.PI/180);
}

function formatDistance(distance) {
  if (distance < 1) {
    return `${Math.round(distance * 1000)}m`;
  }
  return `${distance.toFixed(1)}km`;
}

userMenuBtn.addEventListener('click', (e) => {
  e.stopPropagation();
  userMenu.hidden = !userMenu.hidden;
  userMenu.classList.toggle('show');
});

document.addEventListener('click', () => {
  userMenu.hidden = true;
  userMenu.classList.remove('show');
});

userMenu.addEventListener('click', (e) => {
  e.stopPropagation();
});

logoutBtn.addEventListener('click', async () => {
  if (confirm('Deseja realmente sair?')) {
    try {
      await apiRequest('/api/auth/logout', {
        method: 'POST',
        body: JSON.stringify({ refreshToken })
      });
    } catch (error) {
      console.error('Logout error:', error);
    }

    accessToken = null;
    refreshToken = null;
    currentUser = null;
    location.reload();
  }
});

themeToggle.addEventListener('click', () => {
  const html = document.documentElement;
  const newTheme = html.dataset.theme === 'light' ? 'dark' : 'light';

  html.classList.add('theme-transition');
  html.dataset.theme = newTheme;

  themeToggle.classList.add('rotating');

  setTimeout(() => {
    html.classList.remove('theme-transition');
    themeToggle.classList.remove('rotating');
  }, 300);

  if (map) {
    setTimeout(() => {
      map.invalidateSize();
    }, 300);
  }
});

document.addEventListener('DOMContentLoaded', () => {
  initParticles();
  setLoading(false);

  const emailInput = loginForm.querySelector('input[name="email"]');
  if (emailInput) {
    emailInput.focus();
  }
});