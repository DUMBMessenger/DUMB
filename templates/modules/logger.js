export class Logger {
  static info(message, meta = {}) {
    this.log('INFO', message, meta);
  }

  static warn(message, meta = {}) {
    this.log('WARN', message, meta);
  }

  static error(message, meta = {}) {
    this.log('ERROR', message, meta);
  }

  static log(level, message, meta = {}) {
    const logEntry = {
      level,
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
