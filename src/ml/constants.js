// src/ml/constants.js
// ═══════════════════════════════════════════════════════════════
// Shared constants across ML modules - eliminates duplicates
// ═══════════════════════════════════════════════════════════════

// Attack types for classification
export const ATTACK_TYPES = [
  'normal',
  'credential_stuffing',
  'data_scraping',
  'enumeration',
  'rate_limit_evasion',
  'brute_force',
  'sql_injection',
  'xss',
];

export const NUM_CLASSES = ATTACK_TYPES.length;

// Bot User-Agent patterns for detection
export const BOT_UA_PATTERNS = [
  'python-requests', 'python-urllib', 'python-httpx',
  'curl/', 'wget/', 'httpie/',
  'go-http-client', 'java/', 'okhttp/',
  'scrapy', 'selenium', 'puppeteer', 'playwright',
  'headlesschrome', 'phantomjs',
  'bot', 'crawler', 'spider', 'scraper',
  'apache-httpclient', 'axios/', 'node-fetch',
  'databot', 'libwww-perl',
];

// Browser-standard headers (for missing header detection)
export const BROWSER_HEADERS = [
  'accept-language',
  'sec-ch-ua',
  'sec-ch-ua-mobile',
  'sec-ch-ua-platform',
  'sec-fetch-dest',
  'sec-fetch-mode',
  'sec-fetch-site',
  'upgrade-insecure-requests',
  'cache-control',
];

// Fallback patterns for training when no rules loaded
export const FALLBACK_PATTERNS = [
  { label: 'normal', riskRange: [0, 20], count: 40, generator: {} },
  { label: 'credential_stuffing', riskRange: [70, 98], count: 30, generator: { authPattern: ['basic'], endpointPattern: '/api/auth/login' } },
  { label: 'data_scraping', riskRange: [55, 90], count: 30, generator: { endpointPattern: '/api/users/{id}' } },
  { label: 'enumeration', riskRange: [50, 85], count: 30, generator: { endpointPattern: '/api/products/{id}' } },
  { label: 'rate_limit_evasion', riskRange: [45, 80], count: 20, generator: { authPattern: ['no_auth'] } },
  { label: 'brute_force', riskRange: [75, 99], count: 20, generator: { authPattern: ['basic'], endpointPattern: '/api/auth/login' } },
];

// Realistic body shapes per attack type
export const BODY_SHAPES = {
  normal: ['empty', '{ page: 1, limit: 20 }', '{ q: "" }', '{ sort: "date" }'],
  credential_stuffing: ['{ username: "", password: "" }'],
  data_scraping: ['empty'],
  enumeration: ['empty'],
  rate_limit_evasion: ['empty', '{ page: 1, limit: 50 }'],
  brute_force: ['{ username: "", password: "" }'],
  sql_injection: ['{ id: "1\' OR 1=1--" }'],
  xss: ['{ q: "<script>alert(1)</script>" }'],
};

// User agents per type
export const USER_AGENTS = {
  normal: [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1',
  ],
  bot: [
    'python-requests/2.31.0',
    'curl/8.4.0',
    'python-urllib/3.11',
    'Go-http-client/1.1',
    'Scrapy/2.11.0 (+https://scrapy.org)',
    'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
  ],
};

// Endpoints per attack type
export const ENDPOINTS = {
  normal: [
    '/api/users/1',
    '/api/users/1/profile',
    '/api/products/5',
    '/api/search',
    '/api/listings',
  ],
  credential_stuffing: [
    '/api/auth/login',
    '/api/auth/login',
    '/api/auth/login',
  ],
  data_scraping: [
    '/api/users/{id}',
    '/api/users/{id}/profile',
    '/api/products/{id}',
    '/api/listings',
  ],
  enumeration: [
    '/api/products/{id}',
    '/api/users/{id}',
    '/api/orders/{id}',
  ],
  rate_limit_evasion: [
    '/api/search',
    '/api/listings',
    '/api/users/{id}',
  ],
  brute_force: [
    '/api/auth/login',
    '/api/auth/login',
    '/api/auth/verify',
  ],
};

// Helper to pick random item
export function pick(arr) {
  return arr[Math.floor(Math.random() * arr.length)];
}

// Helper to pick random integer
export function randInt(min, max) {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}