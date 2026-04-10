// test_server/server.js
// ═══════════════════════════════════════════════════════════════
// Realistic E-Commerce API — Protected by Abuse Detection Engine
//
// Features:
//   - MySQL database (users, products, orders)
//   - JWT-like auth tokens
//   - All /api/* routes proxy through the engine on :3000
//   - Sandbox IP blocking (engine blocks, test server enforces)
//   - Realistic response times and data
//
// Usage: npm run test-server
// Requires: MySQL running with root:idkthepassword
// ═══════════════════════════════════════════════════════════════
import express from 'express';
import mysql from 'mysql2/promise';

const app = express();
const PORT = 4000;
const ENGINE_URL = 'http://localhost:3000';

app.use(express.json());

// ── MySQL Connection Pool ────────────────────────────────────
let pool;
async function initDB() {
  pool = mysql.createPool({
    host: 'localhost',
    user: 'root',
    password: 'idkthepassword',
    waitForConnections: true,
    connectionLimit: 10,
  });

  const conn = await pool.getConnection();
  try {
    // Create database
    await conn.query('CREATE DATABASE IF NOT EXISTS suta_testdb');
    await conn.query('USE suta_testdb');

    // Users table
    await conn.query(`
      CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(100) NOT NULL UNIQUE,
        email VARCHAR(255) NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        full_name VARCHAR(200),
        bio TEXT,
        avatar_url VARCHAR(500),
        role ENUM('user', 'admin', 'moderator') DEFAULT 'user',
        is_active BOOLEAN DEFAULT TRUE,
        last_login DATETIME,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
      )
    `);

    // Products table
    await conn.query(`
      CREATE TABLE IF NOT EXISTS products (
        id INT AUTO_INCREMENT PRIMARY KEY,
        name VARCHAR(200) NOT NULL,
        description TEXT,
        price DECIMAL(10,2) NOT NULL,
        category VARCHAR(100),
        stock INT DEFAULT 0,
        sku VARCHAR(50) UNIQUE,
        image_url VARCHAR(500),
        rating DECIMAL(3,2) DEFAULT 0,
        review_count INT DEFAULT 0,
        is_active BOOLEAN DEFAULT TRUE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Orders table
    await conn.query(`
      CREATE TABLE IF NOT EXISTS orders (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT,
        status ENUM('pending', 'processing', 'shipped', 'delivered', 'cancelled') DEFAULT 'pending',
        total DECIMAL(10,2) NOT NULL,
        shipping_address TEXT,
        payment_method VARCHAR(50),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
      )
    `);

    // Order items
    await conn.query(`
      CREATE TABLE IF NOT EXISTS order_items (
        id INT AUTO_INCREMENT PRIMARY KEY,
        order_id INT,
        product_id INT,
        quantity INT NOT NULL,
        price DECIMAL(10,2) NOT NULL,
        FOREIGN KEY (order_id) REFERENCES orders(id) ON DELETE CASCADE,
        FOREIGN KEY (product_id) REFERENCES products(id) ON DELETE SET NULL
      )
    `);

    // Seed data if empty
    const [users] = await conn.query('SELECT COUNT(*) as count FROM users');
    if (users[0].count === 0) {
      console.log('   Seeding database...');
      await seedData(conn);
    }

    console.log('   ✅ Database ready (suta_testdb)');
  } finally {
    conn.release();
  }
}

async function seedData(conn) {
  // Seed users
  const userValues = [];
  for (let i = 1; i <= 100; i++) {
    userValues.push([
      `user${i}`, `user${i}@example.com`, `$2b$10$hash${i}`,
      `User ${i}`, `Bio for user ${i}`, `https://api.dicebear.com/7.x/avataaars/svg?seed=user${i}`,
      i <= 3 ? 'admin' : 'user',
    ]);
  }
  await conn.query(
    'INSERT INTO users (username, email, password_hash, full_name, bio, avatar_url, role) VALUES ?',
    [userValues]
  );

  // Seed products
  const categories = ['Electronics', 'Clothing', 'Books', 'Home', 'Sports', 'Toys', 'Food', 'Beauty'];
  const productValues = [];
  for (let i = 1; i <= 200; i++) {
    productValues.push([
      `Product ${i}`, `Description for product ${i}`,
      (Math.random() * 500 + 5).toFixed(2),
      categories[i % categories.length],
      Math.floor(Math.random() * 500),
      `SKU-${String(i).padStart(5, '0')}`,
      `https://picsum.photos/seed/product${i}/400/400`,
      (Math.random() * 4 + 1).toFixed(2),
      Math.floor(Math.random() * 200),
    ]);
  }
  await conn.query(
    'INSERT INTO products (name, description, price, category, stock, sku, image_url, rating, review_count) VALUES ?',
    [productValues]
  );

  // Seed orders
  for (let i = 1; i <= 50; i++) {
    const userId = Math.floor(Math.random() * 100) + 1;
    const total = (Math.random() * 300 + 20).toFixed(2);
    const [result] = await conn.query(
      'INSERT INTO orders (user_id, total, status, shipping_address, payment_method) VALUES (?, ?, ?, ?, ?)',
      [userId, total, ['pending', 'processing', 'shipped', 'delivered'][Math.floor(Math.random()*4)], `${Math.floor(Math.random()*999)+1} Main St`, 'credit_card']
    );
    const orderId = result.insertId;
    const itemCount = Math.floor(Math.random() * 3) + 1;
    for (let j = 0; j < itemCount; j++) {
      const productId = Math.floor(Math.random() * 200) + 1;
      await conn.query(
        'INSERT INTO order_items (order_id, product_id, quantity, price) VALUES (?, ?, ?, ?)',
        [orderId, productId, Math.floor(Math.random()*5)+1, (Math.random()*100+10).toFixed(2)]
      );
    }
  }

  console.log('   ✓ Seeded 100 users, 200 products, 50 orders');
}

// ── Stats ────────────────────────────────────────────────────
let stats = { total: 0, allowed: 0, blocked: 0, throttled: 0, errors: 0, proxied: 0 };

// ── Proxy middleware — route through abuse engine ─────────────
async function proxyToEngine(req, res) {
  stats.total++;
  const apiPath = req.originalUrl;
  const targetUrl = `${ENGINE_URL}${apiPath}`;

  try {
    const hdrs = {};
    for (const [key, val] of Object.entries(req.headers)) {
      if (!['host', 'content-length', 'connection'].includes(key.toLowerCase())) {
        hdrs[key] = val;
      }
    }
    hdrs['Content-Type'] = 'application/json';

    const clientIp = req.headers['x-forwarded-for'] || req.headers['x-real-ip'] || req.ip || req.socket.remoteAddress;
    hdrs['X-Forwarded-For'] = clientIp;
    hdrs['X-Real-IP'] = clientIp;

    const response = await fetch(targetUrl, {
      method: req.method,
      headers: hdrs,
      body: ['POST', 'PUT', 'PATCH'].includes(req.method.toUpperCase())
        ? JSON.stringify(req.body) : undefined,
    });

    stats.proxied++;
    const data = await response.text();
    let parsed;
    try { parsed = JSON.parse(data); } catch { parsed = data; }

    if (response.status === 403) {
      stats.blocked++;
      return res.status(403).json({
        error: 'BLOCKED',
        message: 'Request blocked by API Abuse Detection Engine',
        engine_response: parsed,
      });
    }
    if (response.status === 429) {
      stats.throttled++;
      return res.status(429).json({
        error: 'THROTTLED',
        message: 'Request throttled',
        engine_response: parsed,
      });
    }

    stats.allowed++;
    res.status(response.status).json(parsed);
  } catch (e) {
    stats.errors++;
    if (e.cause?.code === 'ECONNREFUSED') {
      // Engine offline — serve directly from MySQL
      handleLocal(req, res);
    } else {
      res.status(500).json({ error: 'proxy_error', message: e.message });
    }
  }
}

// ── Direct handlers (used when engine is offline) ────────────
async function handleLocal(req, res) {
  const path = req.path;
  const method = req.method;

  try {
    const conn = await pool.getConnection();
    try {
      await conn.query('USE suta_testdb');

      if (path === '/health' && method === 'GET') {
        return res.json({ status: 'ok', mode: 'direct', db: 'connected' });
      }

      if (path.match(/^\/users\/(\d+)$/) && method === 'GET') {
        const id = path.match(/^\/users\/(\d+)$/)[1];
        const [rows] = await conn.query('SELECT id, username, email, full_name, role, created_at FROM users WHERE id = ?', [id]);
        return rows.length ? res.json(rows[0]) : res.status(404).json({ error: 'User not found' });
      }

      if (path.match(/^\/users\/(\d+)\/profile$/) && method === 'GET') {
        const id = path.match(/^\/users\/(\d+)\/profile$/)[1];
        const [rows] = await conn.query('SELECT id, username, email, full_name, bio, avatar_url, role, created_at FROM users WHERE id = ?', [id]);
        return rows.length ? res.json(rows[0]) : res.status(404).json({ error: 'User not found' });
      }

      if (path.match(/^\/products\/(\d+)$/) && method === 'GET') {
        const id = path.match(/^\/products\/(\d+)$/)[1];
        const [rows] = await conn.query('SELECT * FROM products WHERE id = ?', [id]);
        return rows.length ? res.json(rows[0]) : res.status(404).json({ error: 'Product not found' });
      }

      if (path === '/products' && method === 'GET') {
        const page = parseInt(req.query.page || '1');
        const limit = parseInt(req.query.limit || '20');
        const offset = (page - 1) * limit;
        const category = req.query.category;

        let query = 'SELECT * FROM products WHERE is_active = TRUE';
        const params = [];
        if (category) { query += ' AND category = ?'; params.push(category); }
        query += ' LIMIT ? OFFSET ?';
        params.push(limit, offset);

        const [rows] = await conn.query(query, params);
        const [count] = await conn.query('SELECT COUNT(*) as total FROM products WHERE is_active = TRUE');
        return res.json({ items: rows, total: count[0].total, page, limit });
      }

      if (path === '/search' && method === 'GET') {
        const q = req.query.q || '';
        const [rows] = await conn.query(
          'SELECT id, name, price, category, rating FROM products WHERE name LIKE ? OR description LIKE ? LIMIT 20',
          [`%${q}%`, `%${q}%`]
        );
        return res.json({ query: q, results: rows, count: rows.length });
      }

      if (path === '/auth/login' && method === 'POST') {
        const { username, password } = req.body || {};
        if (!username || !password) return res.status(400).json({ error: 'Username and password required' });
        const [rows] = await conn.query('SELECT id, username, email, role FROM users WHERE username = ?', [username]);
        if (rows.length === 0) return res.status(401).json({ success: false, message: 'Invalid credentials' });
        // In real life we'd check password hash — here we just simulate
        return res.json({ success: false, message: 'Invalid credentials' });
      }

      if (path === '/listings' && method === 'GET') {
        const page = parseInt(req.query.page || '1');
        const [rows] = await conn.query('SELECT id, name, price, category, image_url, rating FROM products LIMIT 20 OFFSET ?', [(page-1)*20]);
        return res.json({ items: rows, page });
      }

      res.status(404).json({ error: 'Not found' });
    } finally {
      conn.release();
    }
  } catch (e) {
    res.status(500).json({ error: 'Database error', message: e.message });
  }
}

// ── Routes ───────────────────────────────────────────────────
app.all('/api/*', proxyToEngine);

app.get('/stats', (req, res) => {
  res.json({
    ...stats,
    uptime: process.uptime().toFixed(0) + 's',
    engine: ENGINE_URL,
    block_rate: stats.total > 0 ? ((stats.blocked / stats.total) * 100).toFixed(1) + '%' : '0%',
  });
});

app.post('/stats/reset', (req, res) => {
  stats = { total: 0, allowed: 0, blocked: 0, throttled: 0, errors: 0, proxied: 0 };
  res.json({ message: 'Stats reset' });
});

app.get('/', (req, res) => {
  res.json({
    name: 'Suta Test E-Commerce API',
    version: '2.0',
    protected_by: 'API Abuse Detection Engine v2.0 (Transformer ML + Hindsight)',
    database: 'MySQL (suta_testdb)',
    endpoints: {
      'GET /api/health': 'Health check',
      'POST /api/auth/login': 'User login (username, password)',
      'GET /api/users/:id': 'Get user by ID',
      'GET /api/users/:id/profile': 'Get full user profile',
      'GET /api/products': 'List products (?page, ?limit, ?category)',
      'GET /api/products/:id': 'Get product by ID',
      'GET /api/search?q=': 'Search products',
      'GET /api/listings': 'Browse product listings',
    },
    stats: '/stats',
  });
});

// ── Start ────────────────────────────────────────────────────
async function start() {
  console.log('');
  console.log('═══════════════════════════════════════════════════');
  console.log('  Suta Test E-Commerce API v2.0');
  console.log('  Protected by: API Abuse Detection Engine');
  console.log('═══════════════════════════════════════════════════');
  console.log('');

  try {
    console.log('   Connecting to MySQL (root@localhost)...');
    await initDB();
  } catch (e) {
    console.error(`   ❌ MySQL connection failed: ${e.message}`);
    console.log('   Server will start but database queries will fail.');
    console.log('   Make sure MySQL is running with:');
    console.log('     user: root');
    console.log('     password: idkthepassword');
    console.log('');
  }

  app.listen(PORT, () => {
    console.log(`   🌐 Server:  http://localhost:${PORT}`);
    console.log(`   🛡️  Engine:  ${ENGINE_URL}`);
    console.log(`   📊 Stats:   http://localhost:${PORT}/stats`);
    console.log('');
    console.log('   All /api/* requests route through the abuse engine.');
    console.log('   Attack this server to see the engine in action.');
    console.log('');
  });
}

start().catch(e => {
  console.error('Fatal:', e);
  process.exit(1);
});
