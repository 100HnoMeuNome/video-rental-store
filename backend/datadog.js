// Initialize Datadog APM tracer - this must be imported and initialized before any other modules
const tracer = require('dd-trace').init({
  service: 'video-rental-api',
  env: process.env.NODE_ENV || 'development',
  version: process.env.APP_VERSION || '1.0.0',

  // APM Configuration
  logInjection: true,
  runtimeMetrics: true,
  profiling: true,

  // Application Security (ASM) Configuration
  appsec: {
    enabled: true,
    // Protection rules
    rules: undefined, // Uses default Datadog rules
    waf: {
      timeout: 5000 // WAF timeout in microseconds
    }
  },

  // IAST (Interactive Application Security Testing) Configuration
  iast: {
    enabled: true,
    requestSampling: 100, // Sample 100% of requests for IAST
    maxConcurrentRequests: 2,
    maxContextOperations: 2
  },

  // Additional APM settings
  analytics: true,
  tags: {
    'team': 'backend',
    'application': 'video-rental-store'
  }
});

module.exports = tracer;
