const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');

const app = express();

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static('public'));

// Database connection
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// JWT Secret
const JWT_SECRET = process.env.JWT_SECRET || 'prime-worktops-secret-key-change-in-production';

// Initialize database tables
async function initDB() {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS companies (
        id SERIAL PRIMARY KEY,
        company_name VARCHAR(255) NOT NULL,
        email VARCHAR(255) UNIQUE NOT NULL,
        phone VARCHAR(20),
        address_line1 VARCHAR(255),
        address_line2 VARCHAR(255),
        city VARCHAR(100),
        postcode VARCHAR(10),
        vat_number VARCHAR(20),
        account_status VARCHAR(20) DEFAULT 'trial',
        trial_ends_at TIMESTAMP DEFAULT (CURRENT_TIMESTAMP + INTERVAL '14 days'),
        markup_percentage DECIMAL(5,2) DEFAULT 20.00,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        company_id INTEGER REFERENCES companies(id),
        email VARCHAR(255) UNIQUE NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        first_name VARCHAR(100) NOT NULL,
        last_name VARCHAR(100) NOT NULL,
        phone VARCHAR(20),
        role VARCHAR(20) DEFAULT 'trade_user',
        is_active BOOLEAN DEFAULT true,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS company_branding (
        id SERIAL PRIMARY KEY,
        company_id INTEGER REFERENCES companies(id) UNIQUE,
        logo_url VARCHAR(500),
        primary_colour VARCHAR(7) DEFAULT '#033f2a',
        secondary_colour VARCHAR(7) DEFAULT '#f6d466',
        quote_header_text TEXT,
        quote_footer_text TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS quotes (
        id SERIAL PRIMARY KEY,
        company_id INTEGER REFERENCES companies(id),
        created_by INTEGER REFERENCES users(id),
        quote_reference VARCHAR(20) UNIQUE NOT NULL,
        status VARCHAR(20) DEFAULT 'draft',
        customer_name VARCHAR(255),
        customer_email VARCHAR(255),
        customer_phone VARCHAR(20),
        customer_address TEXT,
        customer_postcode VARCHAR(10),
        material_name VARCHAR(255),
        material_brand VARCHAR(255),
        thickness INTEGER,
        edge_profile VARCHAR(50),
        slabs_required INTEGER DEFAULT 1,
        trade_price_ex_vat DECIMAL(10,2),
        trade_price_inc_vat DECIMAL(10,2),
        customer_price_ex_vat DECIMAL(10,2),
        customer_price_inc_vat DECIMAL(10,2),
        quote_data JSONB,
        valid_until DATE DEFAULT (CURRENT_DATE + INTERVAL '30 days'),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    console.log('Database tables initialized');
  } catch (err) {
    console.error('Database initialization error:', err);
  }
}

// Generate quote reference
function generateQuoteRef() {
  const year = new Date().getFullYear();
  const random = Math.floor(Math.random() * 9000) + 1000;
  return `PW-${year}-${random}`;
}

// Auth middleware
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  
  if (!token) return res.status(401).json({ error: 'Access denied' });
  
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid token' });
    req.user = user;
    next();
  });
}

// Routes

// Health check
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', time: new Date().toISOString() });
});

// Register company and admin user
app.post('/api/register', async (req, res) => {
  const { companyName, email, password, firstName, lastName, phone, postcode } = req.body;
  
  try {
    // Check if email exists
    const existing = await pool.query('SELECT id FROM users WHERE email = $1', [email]);
    if (existing.rows.length > 0) {
      return res.status(400).json({ error: 'Email already registered' });
    }
    
    // Create company
    const companyResult = await pool.query(
      `INSERT INTO companies (company_name, email, phone, postcode) 
       VALUES ($1, $2, $3, $4) RETURNING id`,
      [companyName, email, phone, postcode]
    );
    const companyId = companyResult.rows[0].id;
    
    // Create default branding
    await pool.query(
      `INSERT INTO company_branding (company_id) VALUES ($1)`,
      [companyId]
    );
    
    // Hash password and create user
    const passwordHash = await bcrypt.hash(password, 10);
    const userResult = await pool.query(
      `INSERT INTO users (company_id, email, password_hash, first_name, last_name, phone, role)
       VALUES ($1, $2, $3, $4, $5, $6, 'trade_admin') RETURNING id`,
      [companyId, email, passwordHash, firstName, lastName, phone]
    );
    
    // Generate token
    const token = jwt.sign(
      { userId: userResult.rows[0].id, companyId, role: 'trade_admin' },
      JWT_SECRET,
      { expiresIn: '7d' }
    );
    
    res.json({ 
      success: true, 
      token,
      user: { firstName, lastName, email, role: 'trade_admin' },
      company: { id: companyId, name: companyName }
    });
  } catch (err) {
    console.error('Registration error:', err);
    res.status(500).json({ error: 'Registration failed' });
  }
});

// Login
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  
  try {
    const result = await pool.query(
      `SELECT u.*, c.company_name, c.account_status 
       FROM users u 
       JOIN companies c ON u.company_id = c.id 
       WHERE u.email = $1`,
      [email]
    );
    
    if (result.rows.length === 0) {
      return res.status(400).json({ error: 'Invalid email or password' });
    }
    
    const user = result.rows[0];
    const validPassword = await bcrypt.compare(password, user.password_hash);
    
    if (!validPassword) {
      return res.status(400).json({ error: 'Invalid email or password' });
    }
    
    const token = jwt.sign(
      { userId: user.id, companyId: user.company_id, role: user.role },
      JWT_SECRET,
      { expiresIn: '7d' }
    );
    
    res.json({
      success: true,
      token,
      user: {
        firstName: user.first_name,
        lastName: user.last_name,
        email: user.email,
        role: user.role
      },
      company: {
        id: user.company_id,
        name: user.company_name,
        status: user.account_status
      }
    });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Login failed' });
  }
});

// Get current user
app.get('/api/me', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT u.id, u.first_name, u.last_name, u.email, u.role,
              c.id as company_id, c.company_name, c.account_status, c.trial_ends_at
       FROM users u
       JOIN companies c ON u.company_id = c.id
       WHERE u.id = $1`,
      [req.user.userId]
    );
    
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: 'Failed to get user' });
  }
});

// Get company branding
app.get('/api/branding', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT cb.*, c.company_name, c.email, c.phone, c.address_line1, 
              c.address_line2, c.city, c.postcode
       FROM company_branding cb
       JOIN companies c ON cb.company_id = c.id
       WHERE cb.company_id = $1`,
      [req.user.companyId]
    );
    res.json(result.rows[0] || {});
  } catch (err) {
    res.status(500).json({ error: 'Failed to get branding' });
  }
});

// Update company branding
app.put('/api/branding', authenticateToken, async (req, res) => {
  const { logoUrl, primaryColour, secondaryColour, quoteHeaderText, quoteFooterText } = req.body;
  
  try {
    await pool.query(
      `UPDATE company_branding 
       SET logo_url = COALESCE($1, logo_url),
           primary_colour = COALESCE($2, primary_colour),
           secondary_colour = COALESCE($3, secondary_colour),
           quote_header_text = COALESCE($4, quote_header_text),
           quote_footer_text = COALESCE($5, quote_footer_text)
       WHERE company_id = $6`,
      [logoUrl, primaryColour, secondaryColour, quoteHeaderText, quoteFooterText, req.user.companyId]
    );
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Failed to update branding' });
  }
});

// Update company details
app.put('/api/company', authenticateToken, async (req, res) => {
  const { companyName, phone, addressLine1, addressLine2, city, postcode, vatNumber } = req.body;
  
  try {
    await pool.query(
      `UPDATE companies 
       SET company_name = COALESCE($1, company_name),
           phone = COALESCE($2, phone),
           address_line1 = COALESCE($3, address_line1),
           address_line2 = COALESCE($4, address_line2),
           city = COALESCE($5, city),
           postcode = COALESCE($6, postcode),
           vat_number = COALESCE($7, vat_number)
       WHERE id = $8`,
      [companyName, phone, addressLine1, addressLine2, city, postcode, vatNumber, req.user.companyId]
    );
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Failed to update company' });
  }
});

// Create quote
app.post('/api/quotes', authenticateToken, async (req, res) => {
  const { customerName, customerEmail, customerPhone, customerAddress, customerPostcode,
          materialName, materialBrand, thickness, edgeProfile, slabsRequired,
          tradePriceExVat, tradePriceIncVat, customerPriceExVat, customerPriceIncVat,
          quoteData } = req.body;
  
  try {
    const quoteRef = generateQuoteRef();
    
    const result = await pool.query(
      `INSERT INTO quotes (company_id, created_by, quote_reference, customer_name, 
        customer_email, customer_phone, customer_address, customer_postcode,
        material_name, material_brand, thickness, edge_profile, slabs_required,
        trade_price_ex_vat, trade_price_inc_vat, customer_price_ex_vat, customer_price_inc_vat,
        quote_data)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18)
       RETURNING *`,
      [req.user.companyId, req.user.userId, quoteRef, customerName, customerEmail,
       customerPhone, customerAddress, customerPostcode, materialName, materialBrand,
       thickness, edgeProfile, slabsRequired, tradePriceExVat, tradePriceIncVat,
       customerPriceExVat, customerPriceIncVat, JSON.stringify(quoteData)]
    );
    
    res.json(result.rows[0]);
  } catch (err) {
    console.error('Create quote error:', err);
    res.status(500).json({ error: 'Failed to create quote' });
  }
});

// Get all quotes for company
app.get('/api/quotes', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT q.*, u.first_name, u.last_name
       FROM quotes q
       LEFT JOIN users u ON q.created_by = u.id
       WHERE q.company_id = $1
       ORDER BY q.created_at DESC`,
      [req.user.companyId]
    );
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: 'Failed to get quotes' });
  }
});

// Get single quote
app.get('/api/quotes/:id', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT q.*, u.first_name, u.last_name
       FROM quotes q
       LEFT JOIN users u ON q.created_by = u.id
       WHERE q.id = $1 AND q.company_id = $2`,
      [req.params.id, req.user.companyId]
    );
    
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Quote not found' });
    }
    
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: 'Failed to get quote' });
  }
});

// Update quote status
app.patch('/api/quotes/:id/status', authenticateToken, async (req, res) => {
  const { status } = req.body;
  
  try {
    await pool.query(
      `UPDATE quotes SET status = $1 WHERE id = $2 AND company_id = $3`,
      [status, req.params.id, req.user.companyId]
    );
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Failed to update quote' });
  }
});

// Serve frontend
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Start server
const PORT = process.env.PORT || 3000;

initDB().then(() => {
  app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
  });
});
