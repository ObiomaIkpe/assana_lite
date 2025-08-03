// src/config/configuration.ts
export default () => ({
  database: {
    host: process.env.DATABASE_HOST,
    port: parseInt(process.env.DATABASE_PORT!, 10) || 5432,
    username: process.env.DATABASE_USERNAME,
    password: process.env.DATABASE_PASSWORD,
    database: process.env.DATABASE_NAME,
  },
  redis: {
    host: process.env.REDIS_HOST,
    port: parseInt(process.env.REDIS_PORT!, 10) || 6379,
    password: process.env.REDIS_PASSWORD,
  },
  jwt: {
    secret: process.env.JWT_SECRET,
    expiresIn: process.env.JWT_EXPIRES_IN,
    refreshSecret: process.env.JWT_REFRESH_SECRET,
    refreshExpiresIn: process.env.JWT_REFRESH_EXPIRES_IN,
  },
  email: {
    host: process.env.SMTP_HOST,
    port: parseInt(process.env.SMTP_PORT!, 10) || 587,
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS,
    from: process.env.FROM_EMAIL,
  },
  app: {
    nodeEnv: process.env.NODE_ENV,
    port: parseInt(process.env.PORT!, 10) || 3000,
    url: process.env.APP_URL,
  },
  upload: {
    maxFileSize: parseInt(process.env.MAX_FILE_SIZE!, 10) || 10485760,
    uploadDir: process.env.UPLOAD_DIR || './uploads',
  },
  throttle: {
    ttl: parseInt(process.env.THROTTLE_TTL ?? '10', 10),
    limit: parseInt(process.env.THROTTLE_LIMIT ?? '10', 10),
  },
});

// src/config/database.config.ts


// src/config/redis.config.ts


// src/config/validation.schema.ts
