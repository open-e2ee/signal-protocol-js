/**
 * Signal package logging primitives.
 *
 * The package resolves a logger once at composition time and passes it through
 * explicit dependencies. This keeps logging package-local without relying on
 * mutable module-global state.
 */

export interface ILogger {
  debug?(message: string, data?: unknown): void;
  info?(message: string, data?: unknown): void;
  warn?(message: string, data?: unknown): void;
  error?(message: string, errorOrData?: Error | unknown, data?: unknown): void;
  breadcrumb?(message: string, data?: unknown): void;
}

function createDefaultLogger(): ILogger {
  const isDev = typeof __DEV__ !== 'undefined' && __DEV__;
  const isTest = typeof process !== 'undefined' && process.env.NODE_ENV === 'test';

  if (isTest) {
    return {};
  }

  if (isDev) {
    return {
      debug: console.debug.bind(console),
      info: console.info.bind(console),
      warn: console.warn.bind(console),
      error: console.error.bind(console),
      breadcrumb: console.debug.bind(console),
    };
  }

  return {
    warn: console.warn.bind(console),
    error: console.error.bind(console),
  };
}

export function createDefaultSignalLogger(): ILogger {
  return createDefaultLogger();
}

const baseDefaultLogger = createDefaultLogger();

export const defaultSignalLogger: Required<ILogger> = {
  debug: (message: string, data?: unknown): void => {
    baseDefaultLogger.debug?.(message, data);
  },
  info: (message: string, data?: unknown): void => {
    baseDefaultLogger.info?.(message, data);
  },
  warn: (message: string, data?: unknown): void => {
    baseDefaultLogger.warn?.(message, data);
  },
  error: (message: string, errorOrData?: Error | unknown, data?: unknown): void => {
    baseDefaultLogger.error?.(message, errorOrData, data);
  },
  breadcrumb: (message: string, data?: unknown): void => {
    baseDefaultLogger.breadcrumb?.(message, data);
  },
};

export function resolveSignalLogger(logger?: ILogger): Required<ILogger> {
  if (!logger) {
    return defaultSignalLogger;
  }

  return {
    debug: (message: string, data?: unknown): void => {
      logger.debug?.(message, data);
    },
    info: (message: string, data?: unknown): void => {
      logger.info?.(message, data);
    },
    warn: (message: string, data?: unknown): void => {
      logger.warn?.(message, data);
    },
    error: (message: string, errorOrData?: Error | unknown, data?: unknown): void => {
      logger.error?.(message, errorOrData, data);
    },
    breadcrumb: (message: string, data?: unknown): void => {
      logger.breadcrumb?.(message, data);
    },
  };
}
