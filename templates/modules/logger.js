export class Logger {
  constructor(config = {}) {
    this.config = config;
  }

  info(module, message, meta = {}) {
    this.log('INFO', module, message, meta);
  }

  warn(module, message, meta = {}) {
    this.log('WARN', module, message, meta);
  }

  error(module, message, meta = {}) {
    this.log('ERROR', module, message, meta);
  }

  debug(module, message, meta = {}) {
    this.log('DEBUG', module, message, meta);
  }

  log(level, module, message, meta = {}) {
    const logEntry = {
      level,
      module,
      message,
      timestamp: new Date().toISOString(),
      ...meta
    };

    const logString = JSON.stringify(logEntry);
    
    switch (level) {
      case 'ERROR':
        console.error(logString);
        break;
      case 'WARN':
        console.warn(logString);
        break;
      default:
        console.log(logString);
    }
  }
}
