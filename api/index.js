// api/index.js
const express = require('express');
const mysql = require('mysql2');
const cors = require('cors'); // Retained if needed elsewhere in your stack
const bcrypt = require('bcryptjs');
const serverless = require('serverless-http'); // Wraps Express for Serverless
const fs = require('fs').promises;             // Required for reading the root fallback JSON file
const path = require('path');                  // Required for building precise directory pathways

const app = express();

// 1. UNIFIED SECURITY, CORS, & PRIVATE NETWORK ACCESS LIFECYCLE ENGINE
const allowedOrigins = [
    'https://dts-cc.vercel.app', 
    'http://localhost:3000', 
    'http://localhost:5000',
    'http://127.0.0.1:5500/'
];

app.use((req, res, next) => {
    const origin = req.headers.origin;
    
    // Echo back the active matching origin to satisfy secure CORS policies
    if (allowedOrigins.includes(origin)) {
        res.setHeader("Access-Control-Allow-Origin", origin);
    }
    
    // Core authorization headers configuration
    res.setHeader("Access-Control-Allow-Credentials", "true");
    res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept, Authorization, Access-Control-Allow-Private-Network");
    
    // CRITICAL: Permits public Vercel links to cleanly request resources from your local network boundary
    res.setHeader("Access-Control-Allow-Private-Network", "true");

    // Intercept and resolve preflight OPTIONS queries instantly before routing engine engagement
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

// 5. LIVE INVENTORY SYNC ROUTE WITH ROOT JSON FILE FALLBACK
app.get('/api/products', async (req, res) => {
    try {
        // Primary Attempt: Try fetching directly from the live database
        const [rows] = await db.query('SELECT * FROM product');
        
        if (rows && rows.length > 0) {
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
        
        // Throw to fallback loop if query finishes but database returns 0 rows
        throw new Error("No live database entries found. Shifting to static file.");

    } catch (err) {
        console.warn("Database unavailable. Engaging root directory fallback JSON protocol:", err.message);
        
        try {
            // Secondary Attempt: Target and read products.json from the parent root folder
            const jsonPath = path.join(__dirname, '..', 'products.json');
            const fileData = await fs.readFile(jsonPath, 'utf8');
            const fallbackProducts = JSON.parse(fileData);

            // Format data keys dynamically to guarantee matching API payloads
            const formattedFallback = fallbackProducts.map(p => ({
                id: p.Product_ID || p.id,
                name: p.Name || p.name,
                category: (p.Category || p.category || 'Women').toLowerCase(),
                detail: p.Detail || p.detail || p.Description,
                price: p.Price || p.price,
                img: p.Img_Url || p.Img_URL || p.img_url || p.Img_url || "", 
                badge: p.Badge || p.badge || null
            }));

            return res.status(200).json(formattedFallback);

        } catch (fallbackErr) {
            console.error("Critical Failure: Both database and root products.json are missing/unreadable.", fallbackErr);
            return res.status(500).send("Database and static fallback files both unavailable.");
        }
    }
});

// 6. EXPORT FOR VERCEL SERVERLESS ENVIRONMENT
module.exports = app;
module.exports.handler = serverless(app);