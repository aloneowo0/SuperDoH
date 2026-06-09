/**
 * Structured logging utility — JSON log events for Workers-DoH v2.
 */

function logEvent(level, event, data) {
  var payload = { timestamp: new Date().toISOString(), level: level, event: event };
  for (var k in data) { if (data.hasOwnProperty(k)) payload[k] = data[k]; }
  var line = JSON.stringify(payload);
  if (level === 'error') console.error(line);
  else if (level === 'warn') console.warn(line);
  else console.log(line);
}

export { logEvent };
