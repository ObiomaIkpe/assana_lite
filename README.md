# 🧩 Assana-Lite

**Assana-Lite** is a lightweight project and task management tool inspired by [Asana](https://asana.com), built with modern backend technologies. Ideal for personal productivity or small teams.

---

## 🚀 Project Status

✅ **Authentication implemented (NestJS)**  
🔧 More features coming soon (Tasks, Projects, Teams, etc.)

---

## 🔐 Features (So Far)

### ✅ Authentication Module
- User Registration
- User Login
- Password Hashing with `bcrypt`
- JWT-based Authentication
- Protected Routes with Guards

---

## 🛠 Tech Stack

- **Backend:** [NestJS](https://nestjs.com/) (TypeScript)
- **Auth:** JWT, `@nestjs/passport`, `@nestjs/jwt`
- **Database:** [Your choice here, e.g., PostgreSQL via TypeORM/Prisma/Mongoose]
- **Environment Variables:** Managed via `.env`

---

## 📁 Folder Structure

```
assana-lite/
├── src/
│   ├── auth/           # Authentication logic (controller, service, DTOs, etc.)
│   ├── users/          # User module (if separated)
│   ├── app.module.ts   # Root module
│   └── main.ts         # Entry point
├── test/               # Unit tests
├── .env                # Environment config
├── package.json
└── README.md
```

---

## ⚙️ Getting Started

### 1. Clone the Repo

```bash
git clone https://github.com/yourusername/assana-lite.git
cd assana-lite
```

### 2. Install Dependencies

```bash
npm install
```

### 3. Configure Environment Variables

Create a `.env` file in the root and set the following:

```env
JWT_SECRET=your_jwt_secret
JWT_EXPIRES_IN=3600s
DATABASE_URL=your_database_url
PORT=3000
```

> Adjust `DATABASE_URL` depending on whether you're using PostgreSQL, MySQL, or MongoDB.

### 4. Run the Server

```bash
npm run start:dev
```

---

## ✅ Current Endpoints

| Method | Endpoint       | Description       | Auth Required |
|--------|----------------|-------------------|---------------|
| POST   | `/auth/signup` | Register a user   | ❌ No         |
| POST   | `/auth/login`  | Log in a user     | ❌ No         |
| GET    | `/profile`     | Get user profile  | ✅ Yes        |

---

## 🛣️ Roadmap

- [x] Authentication (Sign up/Login + JWT)
- [ ] User roles and permissions
- [ ] Project creation & collaboration
- [ ] Task assignment and tracking
- [ ] Due dates, tags, and filters
- [ ] Notifications system
- [ ] REST or GraphQL API

---

## 🧪 Testing

```bash
npm run test
```

---

## 🤝 Contributing

Pull requests and feature suggestions are welcome!

---

## 📄 License

MIT License

---

## 👤 Author

Built with NestJS by [Your Name](https://github.com/yourusername)
