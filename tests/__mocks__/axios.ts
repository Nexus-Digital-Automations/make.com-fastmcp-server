/**
 * Mock implementation of axios for Jest tests
 * Provides predictable HTTP request/response behavior
 */

import { jest } from '@jest/globals';

const mockAxios = {
  create: jest.fn(() => mockAxios),
  get: jest.fn(() => Promise.resolve({ data: {}, status: 200, statusText: 'OK' })),
  post: jest.fn(() => Promise.resolve({ data: {}, status: 200, statusText: 'OK' })),
  put: jest.fn(() => Promise.resolve({ data: {}, status: 200, statusText: 'OK' })),
  patch: jest.fn(() => Promise.resolve({ data: {}, status: 200, statusText: 'OK' })),
  delete: jest.fn(() => Promise.resolve({ data: {}, status: 200, statusText: 'OK' })),
  head: jest.fn(() => Promise.resolve({ data: {}, status: 200, statusText: 'OK' })),
  options: jest.fn(() => Promise.resolve({ data: {}, status: 200, statusText: 'OK' })),
  request: jest.fn(() => Promise.resolve({ data: {}, status: 200, statusText: 'OK' })),
  interceptors: {
    request: {
      use: jest.fn(),
      eject: jest.fn(),
    },
    response: {
      use: jest.fn(),
      eject: jest.fn(),
    },
  },
  defaults: {
    headers: {},
    timeout: 0,
  },
};

export default mockAxios;