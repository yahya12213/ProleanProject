import request from 'supertest';
import { app } from '../index';

describe('GET /api/health', () => {
  it('should return 200 and health message', async () => {
    const res = await request(app).get('/api/health');
    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('message');
  });
});
