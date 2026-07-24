/**
 * Structured logging utility — JSON log events for SuperDoH.
 * Controlled by LOG_LEVEL config (debug > info > warn > error > none).
 */
const _levels = { debug: 0, info: 1, warn: 2, error: 3, none: 99 };
let _minLevel = 1; // default: info

function setLogLevel(level) {
  if (_levels.hasOwnProperty(level)) _minLevel = _levels[level];
}

function logEvent(level, event, data) {
  if (_levels[level] < _minLevel) return;
  const payload = { timestamp: new Date().toISOString(), level: level, event: event };
  for (let k in data) { if (data.hasOwnProperty(k)) payload[k] = data[k]; }
  const line = JSON.stringify(payload);
  if (level === 'error') console.error(line);
  else if (level === 'warn') console.warn(line);
  else console.log(line);
}

export { logEvent, setLogLevel };
