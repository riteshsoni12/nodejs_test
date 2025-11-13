const express = require('express');
const mysql = require('mysql2');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');

const app = express();
const port = 3000;
const secretKey = 'mySecretKey123'; // 🔑 change this to a strong secret key

app.use(express.json());

// MySQL connection
const db = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASS,
  database: process.env.DB_NAME
});

db.connect(err => {
  if (err) {
    console.error('Database connection failed: ' + err.stack);
    return;
  }
  console.log('Connected to MySQL database.');
});

// Middleware to check JWT
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // "Bearer TOKEN"

  if (!token) return res.status(401).json({ message: 'Access Denied: No Token Provided' });

  jwt.verify(token, secretKey, (err, user) => {
    if (err) return res.status(403).json({ message: 'Invalid Token' });
    req.user = user;
    next();
  });
}

// Register new user (with hashed password + profile)
app.post('/register', async (req, res) => {
  const { name, email, password } = req.body;

  const connection = db; // assuming db is your MySQL connection

  try {
    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Step 1: Insert user
    const userResult = await new Promise((resolve, reject) => {
      connection.query(
        'INSERT INTO users (name, email, password, created_at) VALUES (?, ?, ?, NOW())',
        [name, email, hashedPassword],
        (err, result) => {
          if (err) return reject(err);
          resolve(result);
        }
      );
    });

    const userId = userResult.insertId;

    // Step 2: Create default profile
    const nameParts = name.trim().split(" ", 2);
    const firstName = nameParts[0];
    const lastName = nameParts[1] || '';

    const profileResult = await new Promise((resolve, reject) => {
      connection.query(
        'INSERT INTO profile (user_id, first_name, last_name, email, account_type, created_at) VALUES (?, ?, ?, ?, ?, NOW())',
        [userId, firstName, lastName, email, 'music_lover'],
        (err, result) => {
          if (err) return reject(err);
          resolve(result);
        }
      );
    });

    const profileId = profileResult.insertId;

    // Step 3: Update user with default profile reference
    await new Promise((resolve, reject) => {
      connection.query(
        'UPDATE users SET default_profile_id = ?, default_profile_type = ? WHERE id = ?',
        [profileId, 'music_lover', userId],
        (err, result) => {
          if (err) return reject(err);
          resolve(result);
        }
      );
    });

    res.status(201).json({
      message: 'User registered successfully!',
      user_id: userId,
      profile_id: profileId
    });

  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Registration failed' });
  }
});


// Login route (generate JWT)
app.post('/login', (req, res) => {
  const { email, password } = req.body;

  db.query('SELECT * FROM users WHERE email = ?', [email], async (err, results) => {
    if (err) throw err;
    if (results.length === 0) return res.status(400).json({ message: 'User not found' });

    const user = results[0];
    const validPassword = await bcrypt.compare(password, user.password);

    if (!validPassword) return res.status(400).json({ message: 'Invalid password' });

    // Generate JWT
    const token = jwt.sign({ id: user.id, email: user.email }, secretKey, { expiresIn: '1h' });

    res.json({ message: 'Login successful', token });
  });
});

// 🔒 Protected route - only accessible with valid JWT
app.get('/users', authenticateToken, (req, res) => {
  db.query('SELECT id, name, email FROM users', (err, results) => {
    if (err) throw err;
    res.json(results);
  });
});


// Get all profiles of a particular user
app.get('/users/:id/profiles', (req, res) => {
  const userId = req.params.id;

  db.query(
    'SELECT id, user_id, first_name, last_name, email, account_type, created_at FROM profile WHERE user_id = ?',
    [userId],
    (err, results) => {
      if (err) {
        console.error(err);
        return res.status(500).json({ error: 'Database error' });
      }

      if (results.length === 0) {
        return res.status(404).json({ message: 'No profiles found for this user' });
      }

      res.json({ profiles: results });
    }
  );
});

app.get('/api/test', (req, res) => {
  res.json({ message: 'Hello from your Node.js API!' });
});


// === Login API ===
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;

  if (username === 'admin' && password === '12345') {
    res.json({
      status: 'success',
      message: 'Login successful',
      token: 'abc123xyz'
    });
  } else {
    res.status(401).json({
      status: 'error',
      message: 'Invalid username or password'
    });
  }
});

// === User Info API ===
app.get('/api/user/:id', (req, res) => {
  const { id } = req.params;

  const fakeUsers = {
    1: { id: 1, name: 'John Doe', email: 'john@example.com' },
    2: { id: 2, name: 'Jane Smith', email: 'jane@example.com' }
  };

  const user = fakeUsers[id];

  if (user) {
    res.json({
      status: 'success',
      user
    });
  } else {
    res.status(404).json({
      status: 'error',
      message: 'User not found'
    });
  }
});

app.listen(port, () => {
  console.log(`Server running on http://localhost:${port}`);
});
