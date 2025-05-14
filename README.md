
# Sistema de Cadastro de Usuários com Localização

Este projeto é uma aplicação backend desenvolvida em Node.js, que realiza o cadastro de usuários com suas informações pessoais, incluindo nome, CPF, email, senha e localização (latitude e longitude). As informações são armazenadas em um banco de dados SQLite. A aplicação também oferece funcionalidades de login e manipulação de dados de usuários.

## Tecnologias Utilizadas

- **Node.js**: Plataforma JavaScript no lado do servidor.
- **Express**: Framework para construção de APIs em Node.js.
- **SQLite3**: Banco de dados local utilizado para armazenar os dados dos usuários.
- **Axios**: Biblioteca para realizar requisições HTTP.
- **CORS**: Permite comunicação entre o frontend e o backend de diferentes origens.
- **Bcryptjs**: Biblioteca para criptografar senhas dos usuários.

## Pré-requisitos

- **Node.js** instalado na sua máquina.
- **SQLite3** para interagir com o banco de dados SQLite.

### Instalação do Node.js

Se ainda não tiver o Node.js, você pode baixá-lo [aqui](https://nodejs.org/).

### Instalação do SQLite3 (se necessário)

Caso precise interagir diretamente com o banco de dados SQLite, siga os passos abaixo:

1. Baixe o [sqlite-tools](https://www.sqlite.org/download.html).
2. Extraia o arquivo e adicione o caminho da pasta onde o `sqlite3.exe` foi extraído ao **caminho de sistema** do Windows.

## Como Rodar o Projeto

### Passo 1: Clonar o repositório

```bash
git clone https://github.com/seu-usuario/seu-repositorio.git
cd seu-repositorio
```

### Passo 2: Instalar as dependências

No diretório do projeto, instale as dependências necessárias utilizando o npm:

```bash
npm install
```

### Passo 3: Rodar o servidor

Execute o seguinte comando para rodar o servidor Node.js:

```bash
node index.js
```

Isso fará o servidor rodar na porta 3000, acessível em `http://localhost:3000`.

### Passo 4: Frontend (HTML)

Abra o arquivo `index.html` diretamente no navegador ou utilize um servidor local, como o **Live Server** no Visual Studio Code, para interagir com a API.

## Endpoints da API

### 1. **POST /criar-usuario**
Responsável pelo cadastro de um novo usuário.

#### Body da requisição:
```json
{
  "nome": "Nome do Usuário",
  "cpf": "000.000.000-00",
  "email": "email@dominio.com",
  "senha": "senha-segura",
  "latitude": "12.3456",
  "longitude": "98.7654"
}
```

#### Resposta:
- Sucesso:
  ```json
  {
    "success": true,
    "message": "Usuário criado com sucesso!"
  }
  ```
- Erro:
  ```json
  {
    "success": false,
    "message": "Erro ao criar usuário. Verifique se o CPF ou Email já está cadastrado."
  }
  ```

### 2. **POST /login**
Responsável pelo login de um usuário, usando email e senha.

#### Body da requisição:
```json
{
  "email": "email@dominio.com",
  "senha": "senha-segura"
}
```

#### Resposta:
- Sucesso:
  ```json
  {
    "success": true,
    "message": "Login realizado com sucesso!",
    "nome": "Nome do Usuário"
  }
  ```
- Erro:
  ```json
  {
    "success": false,
    "message": "Email ou senha incorretos."
  }
  ```

## Estrutura do Banco de Dados

O banco de dados SQLite armazena as informações dos usuários na tabela `Usuarios` com os seguintes campos:

- **id**: ID do usuário (auto-incrementado)
- **nome**: Nome do usuário
- **cpf**: CPF do usuário (único)
- **email**: Email do usuário (único)
- **senha**: Senha criptografada do usuário
- **latitude**: Latitude da localização do usuário
- **longitude**: Longitude da localização do usuário

## Como Interagir com o Banco de Dados

- Para acessar diretamente o banco de dados SQLite, utilize a ferramenta `sqlite3` no terminal:
  ```bash
  sqlite3 database.sqlite
  ```
- Para visualizar as tabelas:
  ```sql
  .tables
  ```
- Para visualizar os dados da tabela `Usuarios`:
  ```sql
  SELECT * FROM Usuarios;
  ```

## Considerações Finais

Esse projeto serve como um exemplo de integração entre Node.js, SQLite, e o uso de APIs RESTful para gerenciamento de usuários com informações pessoais e localização. Ele pode ser expandido para incluir funcionalidades como validação de dados, envio de e-mails, entre outros.

## Licença

Este projeto está licenciado sob a Licença MIT - veja o arquivo [LICENSE](LICENSE) para mais detalhes.
