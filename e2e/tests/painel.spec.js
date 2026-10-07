const { test, expect } = require('@playwright/test');

async function entrar(page, usuario, senha) {
  await page.goto('/');
  await page.fill('#lu', usuario);
  await page.fill('#lp', senha);
  await page.click('#lb');
}

test('senha errada mostra o erro e não entra', async ({ page }) => {
  await entrar(page, 'admin', 'senha-errada');
  await expect(page.locator('#le')).toContainText('incorretos');
  await expect(page.locator('#login')).toBeVisible();
});

test('o administrador entra e vê a visão geral', async ({ page }) => {
  await entrar(page, 'admin', 'senha-admin-123');
  await expect(page.locator('#ttl')).toHaveText('Visão geral');
  await expect(page.locator('#who')).toContainText('administrador');
});

test('simular um ataque gera um alerta na tela', async ({ page }) => {
  await entrar(page, 'admin', 'senha-admin-123');
  await page.click('#bBrute');
  await expect(page.locator('#recent .al').first()).toBeVisible({ timeout: 20_000 });
});

test('o analista não vê Auditoria, Usuários nem Fontes de logs', async ({ page }) => {
  await entrar(page, 'analista', 'senha-analista-123');
  await expect(page.locator('#ttl')).toHaveText('Visão geral');
  for (const v of ['audit', 'users', 'keys']) await expect(page.locator(`[data-v="${v}"]`)).toBeHidden();
});

test('o administrador bloqueia o IP de um alerta e ele aparece em Bloqueios', async ({ page }) => {
  await entrar(page, 'admin', 'senha-admin-123');
  await page.click('#bScan');
  const linha = page.locator('#recent .al').first();
  await expect(linha).toBeVisible({ timeout: 20_000 });
  await linha.click();
  await page.locator('[data-block]').first().click();
  await page.click('[data-v="blocks"]');
  await expect(page.locator('#blocks .tr').first()).toBeVisible();
});

test('sair leva de volta à tela de entrada', async ({ page }) => {
  await entrar(page, 'admin', 'senha-admin-123');
  await page.click('#bOut');
  await expect(page.locator('#login')).toBeVisible();
});
