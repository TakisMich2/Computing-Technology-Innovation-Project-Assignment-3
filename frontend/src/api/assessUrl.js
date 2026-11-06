/** Setup for the FastAPI client backedn here -> backend/app/main.py
 *  POST assess (where body is { "url": "<url>" })
 * 200 -> { url, analysed_url, trust_score, phishing_probability, prediction,
 *              warnings: [{ part, text, reason }], note }
 * GET health
 * 200 -> 200 -> { status: "ok", model_loaded, max_url_length }
 *   Every error -> { error: { code, message, details?, request_id? } }
 */

import { ApiError } from './ApiError.js';

const API_BASE = (import.meta.env.VITE_API_BASE_URL || '').replace(/\/$/, '');
const REQUEST_TIMEOUT_MS = 15000;

function isValidResult(data) {
  return (
    data &&
    typeof data.trust_score === 'number' &&
    typeof data.phishing_probability === 'number' &&
    typeof data.url === 'string' &&
    Array.isArray(data.warnings)
  );
}

async function readError(response) {
  try {
    const body = await response.json();
    return body?.error && typeof body.error.message === 'string' ? body.error : null;
  } catch {
    return null;
  }
}

async function request(path, { signal, ...options }) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
  const cancel = () => controller.abort();
  signal?.addEventListener('abort', cancel);

  try {
    return await fetch(`${API_BASE}${path}`, {
      ...options,
      headers: { Accept: 'application/json', ...options.headers },
      signal: controller.signal,
    });
  } catch (error) {
    if (signal?.aborted) throw error;
    if (controller.signal.aborted) {
      throw new ApiError('The analysis server took too long to respond. Please try again.', 'timeout');
    }
    throw new ApiError(
      'We could not reach the analysis server. Check that the back end is running, then try again.',
      'network',
    );
  } finally {
    clearTimeout(timer);
    signal?.removeEventListener('abort', cancel);
  }
}

/**
 * @param {string} url - this should be an already validated URL
 * @param {{ signal?: AbortSignal }} options - abort to cancel and rejected with aborterror
 */
export async function assessUrl(url, { signal } = {}) {
  const response = await request('/api/assess', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url }),
    signal,
  });

  if (!response.ok) {
    const error = await readError(response);
    const { status } = response;
    if (status === 503 || status === 429) {
      throw new ApiError(error?.message || 'The server is busy. Please wait a few seconds and try again.', 'busy', status);
    }
    if (status >= 400 && status < 500) {
      throw new ApiError(error?.message || 'The server could not read that address. Check it and try again.', 'invalid-input', status);
    }
    throw new ApiError(
      error?.message || 'The analysis server ran into a problem. Please try again in a moment.',
      'server',
      status,
      error?.request_id,
    );
  }

  let data;
  try {
    data = await response.json();
  } catch {
    data = null;
  }
  if (!isValidResult(data)) {
    throw new ApiError('The server sent back a result we could not read. Please try again.', 'bad-response', response.status);
  }
  return data;
}

/** This should resolve true when 2 conditions are met:
 * 1: backend is up/running
 * 2: model is loaded
 **/
export async function checkHealth({ signal } = {}) {
  try {
    const response = await request('/api/health', { method: 'GET', signal });
    if (!response.ok) return false;
    const body = await response.json();
    return body?.status === 'ok' && body.model_loaded === true;
  } catch (error) {
    if (error?.name === 'AbortError') throw error;
    return false;
  }
}
