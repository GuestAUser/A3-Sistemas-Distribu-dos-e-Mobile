# Projeto Fitness – Encontrador de Parques

**Versão API:** 2.45.3 • **Autor:** [GuestAUser](https://github.com/GuestAUser)

Um aplicativo full-stack que localiza parques públicos próximos a um CEP brasileiro, fornecendo um mapa interativo, estatísticas e histórico de buscas personalizadas. 100 % em JavaScript/Node 23, sem dependências externas de servidores ou bancos além de serviços públicos de geocodificação.

---

## 🔍 Visão geral do funcionamento

1. **Autenticação** – O usuário cria conta / faz login (credenciais criptografadas com *bcrypt*).
2. **Geocodificação** – A API transforma o CEP em coordenadas (ViaCEP ➜ Nominatim) com *fallback* para centros urbanos comuns.
3. **Busca de parques** – O servidor consulta a Overpass API (OpenStreetMap) e devolve parques, jardins, playgrounds e reservas naturais num raio configurável.
4. **Histórico inteligente** – Cada CEP pesquisado é registrado; os mais usados aparecem como *chips* para busca rápida.
5. **Frontend reativo** – Interface estática (HTML + CSS + JS) exibe os resultados em lista e em mapa **Leaflet**, com animações suaves e temas claro/escuro.

---

## 🗂️ Estrutura do código

```
.
├── index.js          # API REST (Express 23 + SQLite)
├── db.js             # Configuração e instância do banco
├── public/
│   ├── index.html    # Página única (SPA vanilla)
│   ├── style.css     # Estilos modernos, partículas e responsividade
│   └── script.js     # Lógica de UI, integração com API e Leaflet
└── README.md
```

### Backend (`index.js`)

* **Segurança**: Helmet, CORS restritivo, *rate-limiter* in-memory, validações *Joi*.
* **Logs**: Winston com saída colorida e `HH:mm:ss`.
* **Migrações**: Tabelas `usuarios` e `user_ceps` são criadas automaticamente.
* **Principais rotas**

  | Método | Caminho                  | Descrição                           |
  | ------ | ------------------------ | ----------------------------------- |
  | GET    | `/api/saude`             | Health-check com versão e timestamp |
  | POST   | `/api/usuarios`          | Cria novo usuário                   |
  | POST   | `/api/auth/login`        | Autentica e devolve CEPs recentes   |
  | GET    | `/api/geo/cep/:cep`      | Converte CEP em coordenadas         |
  | GET    | `/api/parques?cep&raio`  | Lista parques próximos              |
  | GET    | `/api/usuarios/:id/ceps` | Histórico do usuário                |
  | DELETE | idem                     | Limpa histórico                     |

### Frontend (`public/*`)

* **index.html** – Estrutura sem frameworks; carrega Leaflet via CDN.
* **style.css** – Tema escuro/claro, partículas, micro-animações (keyframes) e *utility classes* CSS.
* **script.js** – Autenticação, formatação de CEP, chamadas REST, renderização de markers, *chips* de histórico, controle de zoom.

---

## 🚀 Como executar localmente

```bash
# 1. Clone o repositório
$ git clone https://github.com/GuestAUser/projeto-fitness.git && cd projeto-fitness

# 2. Instale dependências
$ npm install

# 3. Configure variáveis de ambiente
$ cp .env.example .env    # edite PORT e ALLOWED_ORIGINS se necessário

# 4. Inicie a API
$ node index.js

# 5. Abra a interface
$ open public/index.html   # ou sirva com qualquer servidor estático
```

> **Banco de dados:** é criado automaticamente como `data.db` na raiz do projeto.

---

## 🗄️ Esquema do banco

```sql
CREATE TABLE usuarios (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  nome TEXT NOT NULL,
  cpf TEXT NOT NULL UNIQUE,
  email TEXT NOT NULL UNIQUE,
  senha TEXT NOT NULL,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE user_ceps (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  cep TEXT NOT NULL,
  search_count INTEGER DEFAULT 1,
  last_searched DATETIME DEFAULT CURRENT_TIMESTAMP,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES usuarios(id) ON DELETE CASCADE,
  UNIQUE (user_id, cep)
);
```

---

## 📈 Roadmap

* Persistência de sessões com JWT ou cookies assinados
* Dockerfile e docker-compose para facilitar deploy
* Troca opcional do SQLite por Postgres
* Testes automatizados (Jest/Supertest)
* Integração CI/CD (GitHub Actions)

---

## 🤝 Contribuindo

1. *Fork* ➜ *branch* ➜ *pull request*.
2. Use *commits* claros (`feat:`, `fix:`, `docs:` …).
3. Respeite o padrão ESLint (**airbnb-base**).

---

## 📜 Licença

Este projeto é distribuído sob a **GuestAUser Public License v1.0 – Sem Uso Comercial**. Leia o arquivo [LICENSE](./LICENSE) para detalhes.
