const { defineConfig } = require('@playwright/test');

// Sobe o servidor de verdade (banco em memória, simulador ligado) e testa o painel num navegador
module.exports = defineConfig({
  testDir: './tests',
  timeout: 45_000,
  retries: process.env.CI ? 1 : 0,
  use: { baseURL: 'http://localhost:3100', trace: 'retain-on-failure' },
  webServer: {
    command: 'node src/server.js',
    cwd: '../backend',
    url: 'http://localhost:3100/api/health',
    reuseExistingServer: !process.env.CI,
    env: {
      PORT: '3100', DB_PATH: ':memory:', JWT_SECRET: 'segredo-e2e', API_KEY: 'chave-e2e',
      ADMIN_PASSWORD: 'senha-admin-123', ANALYST_PASSWORD: 'senha-analista-123',
      SIMULATE: 'true', LOG_LEVEL: 'warn', LOGIN_RATE_LIMIT: '1000',
    },
  },
});
