/**
 * API service for communicating with the backend /analyze endpoint.
 */
import axios from 'axios';

const API_BASE = import.meta.env.VITE_API_URL || '';

const apiClient = axios.create({
  baseURL: API_BASE,
  headers: {
    'Content-Type': 'application/json',
  },
  timeout: 60000,
});

/**
 * Send content for analysis.
 * @param {Object} payload - { input_type, content, options }
 * @returns {Promise<Object>} Analysis response
 */
export async function analyzeContent(payload) {
  try {
    const response = await apiClient.post('/analyze', payload);
    return response.data;
  } catch (error) {
    if (error.response) {
      const detail = error.response.data?.detail;
      throw new Error(
        typeof detail === 'string'
          ? detail
          : JSON.stringify(detail) || `Server error: ${error.response.status}`
      );
    }
    throw new Error('Network error — is the backend running?');
  }
}

/**
 * Check backend health.
 * @returns {Promise<Object>}
 */
export async function checkHealth() {
  const response = await apiClient.get('/health');
  return response.data;
}

/**
 * Interactive chat session for contextual analysis.
 * @param {Object} payload - { message, context }
 * @returns {Promise<Object>} { reply }
 */
export async function sendChatMessage(payload) {
  try {
    const response = await apiClient.post('/chat', payload);
    return response.data;
  } catch (error) {
    if (error.response?.data?.detail) {
      throw new Error(error.response.data.detail);
    }
    throw new Error('Chat service unavailable');
  }
}
