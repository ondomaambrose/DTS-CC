// api/index.js
const express = require('express');
const mysql = require('mysql2');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const serverless = require('serverless-http'); // Wraps Express for Serverless

const app = express();

// 1. ENHANCED SECURITY, CORS, & PRIVATE NETWORK ACCESS CONFIGURATION
const allowedOrigins = ['https://dts-cc.vercel.app', 'http://localhost:3000', 'http://localhost:5000'];

app.use(cors({
    origin: function (origin, callback) {
        // Allow requests with no origin (like mobile apps or curl requests)
        if (!origin) return callback(null, true);
        if (allowedOrigins.indexOf(origin) === -1) {
            const msg = 'The CORS policy for this site does not allow access from the specified Origin.';
            return callback(new Error(msg), false);
        }
        return callback(null, true);
    },
    credentials: true,
    methods: ['GET', 'POST', 'OPTIONS']
}));

// Specialized middleware patch to address Cross-Origin Local Loopback Restrictions
app.use((req, res, next) => {
    const origin = req.headers.origin;
    if (allowedOrigins.includes(origin)) {
        res.header("Access-Control-Allow-Origin", origin);
    }
    res.header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept, Authorization");
    
    // CRITICAL: Explicitly permits public internet deployments to tunnel down to local network boundaries
    res.header("Access-Control-Allow-Private-Network", "true");

    // Immediately capture and resolve preflight OPTIONS headers before routing engine engagement
    if (req.method === 'OPTIONS') {
        return res.sendStatus(200);
    }
    next();
});

app.use(express.json()); 

// 2. CONFIGURE A LIVE DATABASE CONNECTION POOL FOR SERVERLESS
const pool = mysql.createPool({
    host:     process.env.DB_HOST     || '127.0.0.1',
    user:     process.env.DB_USER     || 'root',       
    password: process.env.DB_PASSWORD || '#Spongebob444', 
    database: process.env.DB_NAME     || 'CoutureClassics',
    port:     process.env.DB_PORT     || 3306,
    waitForConnections: true,
    connectionLimit: 5, // Kept light to prevent crashing free cloud database limits
    queueLimit: 0
});

// Use native promises directly from the pool object
const db = pool.promise();

// 3. SIGN-UP / REGISTRATION ROUTE
app.post('/api/signup', async (req, res) => {
    const { firstName, lastName, phone, email, password } = req.body;

    if (!firstName || !lastName || !phone || !email || !password) {
        return res.status(400).json({ error: 'All fields are required' });
    }

    try {
        const [existing] = await db.query('SELECT * FROM CUSTOMER WHERE Email = ?', [email]);
        if (existing.length > 0) {
            return res.status(400).json({ error: 'Email already registered' });
        }

        const customerId = 'CUST' + Math.floor(100000 + Math.random() * 900000);
        const hashedPassword = await bcrypt.hash(password, 10);

        const insertQuery = `
            INSERT INTO CUSTOMER (Customer_ID, First_Name, Last_Name, Phone, Email, Password) 
            VALUES (?, ?, ?, ?, ?, ?)
        `;
        
        await db.query(insertQuery, [customerId, firstName, lastName, phone, email, hashedPassword]);
        res.status(201).json({ message: 'Account successfully created!', customerId });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Internal server registration error' });
    }
});

// 4. SIGN-IN / AUTHENTICATION ROUTE
app.post('/api/signin', async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ error: 'Email and password are required' });
    }

    try {
        const [users] = await db.query('SELECT * FROM CUSTOMER WHERE Email = ?', [email]);
        if (users.length === 0) {
            return res.status(401).json({ error: 'Invalid authentication credentials' });
        }

        const user = users[0];
        const passwordMatch = await bcrypt.compare(password, user.Password);
        if (!passwordMatch) {
            return res.status(401).json({ error: 'Invalid authentication credentials' });
        }

        res.status(200).json({ 
            message: 'Sign in successful!', 
            user: { 
                id: user.Customer_ID, 
                firstName: user.First_Name, 
                lastName: user.Last_Name 
            } 
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Internal server authentication error' });
    }
});

// 5. LIVE INVENTORY SYNC ROUTE
app.get('/api/products', async (req, res) => {
    try {
        const [rows] = await db.query('SELECT * FROM product');
        
        if (rows.length > 0) {
            const formattedProducts = rows.map(p => ({
                id: p.Product_ID || p.id,
                name: p.Name || p.name,
                category: (p.Category || p.category || 'Women').toLowerCase(),
                detail: p.Detail || p.detail || p.Description,
                price: p.Price || p.price,
                img: p.Img_Url || p.Img_URL || p.img_url || p.Img_url || "", 
                badge: p.Badge || p.badge || null
            }));
            
            return res.status(200).json(formattedProducts);
        }
        
        return res.status(200).json([]);
    } catch (err) {
        console.error(err);
        res.status(500).send("Database error");
    }
});

// 6. EXPORT FOR VERCEL
// Serverless environments manage execution lifecycles automatically; app.listen() is removed.
module.exports = app;
module.exports.handler = serverless(app);