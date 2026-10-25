export function assertLoggingDisabled(value) {
  if (value?.enabled !== false || value?.logs?.enabled !== false ||
      value?.logs?.invocation_logs !== false || value?.traces?.enabled !== false) {
    throw new Error('UNSAFE_LOGGING');
  }
}

export function assertCleanBindings(active, latest) {
  if (!Array.isArray(active) || !Array.isArray(latest) || active.length || latest.length) {
    throw new Error('DIRTY_BINDINGS');
  }
}
