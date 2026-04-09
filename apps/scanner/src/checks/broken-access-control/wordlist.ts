export const SENSITIVE_PATHS = [
  // Environment & config
  '/.env', '/.env.local', '/.env.production', '/.env.backup',
  '/config.json', '/config.yml', '/config.yaml', '/config.php',
  '/configuration.json', '/settings.json', '/app.config.js',

  // Admin panels
  '/admin', '/admin/', '/admin/login', '/administrator',
  '/admin/dashboard', '/wp-admin', '/wp-admin/admin-ajax.php',
  '/phpmyadmin', '/phpmyadmin/', '/pma', '/adminer.php',

  // Backup & dumps
  '/backup', '/backup.sql', '/backup.zip', '/backup.tar.gz',
  '/db.sql', '/database.sql', '/dump.sql', '/export.sql',
  '/site.zip', '/www.zip', '/html.zip',

  // Source & version control
  '/.git/config', '/.git/HEAD', '/.svn/entries',
  '/composer.json', '/composer.lock', '/package.json',
  '/Gemfile', '/requirements.txt', '/Pipfile',

  // Server info
  '/phpinfo.php', '/info.php', '/test.php', '/server-status',
  '/server-info', '/.htaccess', '/web.config', '/nginx.conf',

  // API internals
  '/api/v1/users', '/api/users', '/api/admin',
  '/api/config', '/api/debug', '/api/health',
  '/api/v1/admin', '/api/internal',
  '/swagger.json', '/openapi.json', '/api-docs',
  '/swagger-ui.html', '/v1/swagger.json',

  // Logs
  '/logs', '/log', '/error.log', '/access.log',
  '/debug.log', '/app.log', '/storage/logs',

  // Common framework paths
  '/.well-known/security.txt', '/robots.txt', '/sitemap.xml',
  '/crossdomain.xml', '/clientaccesspolicy.xml',
  '/trace.axd', '/elmah.axd',                   // .NET
  '/actuator', '/actuator/env', '/actuator/health', // Spring Boot
  '/metrics', '/debug/pprof',                    // Go
  '/_profiler', '/_wdt',                         // Symfony

  // Upload dirs
  '/uploads', '/upload', '/files', '/static/uploads',

  // Old/temp files
  '/index.php.bak', '/index.bak', '/old', '/temp', '/tmp',
]