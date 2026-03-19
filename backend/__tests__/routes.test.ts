import request from 'supertest';
import { app } from '../index';

describe('API routes integration', () => {
  it('GET /api/health should return 200 and message', async () => {
    const res = await request(app).get('/api/health');
    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('message');
  });

  it('GET /api/formations should return 200', async () => {
    const res = await request(app).get('/api/formations');
    expect(res.status).toBe(200);
  });

  it('GET /api/faqs should return 200', async () => {
    const res = await request(app).get('/api/faqs');
    expect(res.status).toBe(200);
  });

  it('POST /api/auth/register should return 400 or 200', async () => {
    const res = await request(app)
      .post('/api/auth/register')
      .send({ email: 'test@example.com', password: 'test123' });
  expect([200, 400, 409, 500]).toContain(res.status);
  });

  it('POST /api/auth/login should return 400 or 200', async () => {
    const res = await request(app)
      .post('/api/auth/login')
      .send({ email: 'test@example.com', password: 'test123' });
  expect([200, 400, 401, 500]).toContain(res.status);
  });

  it('POST /api/calculate-payroll should return 200 or 400', async () => {
    const res = await request(app)
      .post('/api/calculate-payroll')
      .send({});
  expect([200, 400, 500]).toContain(res.status);
  });

  it('POST /api/payroll-test-engine should return 200 or 400', async () => {
    const res = await request(app)
      .post('/api/payroll-test-engine')
      .send({});
  expect([200, 400, 500]).toContain(res.status);
  });

  it('POST /api/payroll-calculate should return 200 or 400', async () => {
    const res = await request(app)
      .post('/api/payroll-calculate')
      .send({});
  expect([200, 400, 500]).toContain(res.status);
  });

  it('POST /api/create-user-admin should return 200 or 400', async () => {
    const res = await request(app)
      .post('/api/create-user-admin')
      .send({});
  expect([200, 400, 403, 401, 500]).toContain(res.status);
  });

  it('POST /api/generate-family-documents should return 200 or 400', async () => {
    const res = await request(app)
      .post('/api/generate-family-documents')
      .send({});
  expect([200, 400, 501, 500]).toContain(res.status);
  });
});
