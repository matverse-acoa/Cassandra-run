import http from 'k6/http';
import { check, sleep } from 'k6';

export const options = {
  stages: [
    { duration: '30s', target: 50 },
    { duration: '1m', target: 100 },
    { duration: '10s', target: 200 },
    { duration: '30s', target: 0 },
  ],
  thresholds: {
    http_req_duration: ['p(95)<500'],
    http_req_failed: ['rate<0.01'],
  },
};

const BASE_URL = __ENV.BASE_URL || 'http://localhost:8080';
const TOKEN = __ENV.TOKEN || 'seu_token';

export default function () {
  const payload = JSON.stringify({
    type: 'load_test',
    payload: { test: 'data', value: Math.random() },
    metadata: { source: 'k6' },
  });

  const params = {
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${TOKEN}`,
    },
  };

  const res = http.post(`${BASE_URL}/submit`, payload, params);

  check(res, {
    'status is 200 or 201': (r) => r.status === 200 || r.status === 201,
    'response time < 500ms': (r) => r.timings.duration < 500,
  });

  sleep(1);
}
