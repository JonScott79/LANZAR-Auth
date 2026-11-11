export class InitTimeoutError extends Error {
  constructor(message, stage = 'unknown') {
    super(message);
    this.name = 'InitTimeoutError';
    this.code = 'ERR_TIMEOUT';
    this.stage = stage;
  }
}

/**
 * Race a promise against a bounded timeout so Portal initialization never stalls indefinitely.
 */
export function withTimeout(promise, timeoutMs, message, stage = 'unknown') {
  let timerId;
  const timeoutPromise = new Promise((_, reject) => {
    timerId = setTimeout(() => {
      reject(new InitTimeoutError(message || `Operation timed out after ${timeoutMs}ms`, stage));
    }, timeoutMs);
  });

  return Promise.race([Promise.resolve(promise), timeoutPromise]).finally(() => {
    if (timerId !== undefined) {
      clearTimeout(timerId);
    }
  });
}

/**
 * Perform fetch() with an AbortController deadline.
 */
export async function fetchWithTimeout(
  url,
  options = {},
  timeoutMs = 12000,
  timeoutMessage = 'Request timed out. Please try again.',
  stage = 'network'
) {
  const controller = new AbortController();
  let timedOut = false;
  const callerSignal = options.signal;

  const onCallerAbort = () => controller.abort();
  if (callerSignal) {
    if (callerSignal.aborted) {
      controller.abort();
    } else {
      callerSignal.addEventListener('abort', onCallerAbort, { once: true });
    }
  }

  const timerId = setTimeout(() => {
    timedOut = true;
    controller.abort();
  }, timeoutMs);

  try {
    return await fetch(url, { ...options, signal: controller.signal });
  } catch (err) {
    if (timedOut) {
      throw new InitTimeoutError(timeoutMessage, stage);
    }
    throw err;
  } finally {
    clearTimeout(timerId);
    if (callerSignal) {
      callerSignal.removeEventListener('abort', onCallerAbort);
    }
  }
}
