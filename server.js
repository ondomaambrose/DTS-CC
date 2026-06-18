// server.js
const express = require('express');
const mysql = require('mysql2');
const cors = require('cors');
const bcrypt = require('bcryptjs');

const app = express();
app.use(cors());
app.use(express.json()); 

// Configure your MySQL Instance connection
const db = mysql.createConnection({
    host:     process.env.DB_HOST     || '127.0.0.1',
    user:     process.env.DB_USER     || 'root',       
    password: process.env.DB_PASSWORD || '#Spongebob444', 
    database: process.env.DB_NAME     || 'CoutureClassics',
    port:     process.env.DB_PORT     || 3306
});

db.connect((err) => {
    if (err) {
        console.error('Error connecting to MySQL Instance:', err.message);
        return;
    }
    console.log('Connected smoothly to CoutureClassics MySQL database.');
});

// 1. SIGN-UP / REGISTRATION ROUTE
app.post('/api/signup', async (req, res) => {
    const { firstName, lastName, phone, email, password } = req.body;

    if (!firstName || !lastName || !phone || !email || !password) {
        return res.status(400).json({ error: 'All fields are required' });
    }

    try {
        const [existing] = await db.promise().query('SELECT * FROM CUSTOMER WHERE Email = ?', [email]);
        if (existing.length > 0) {
            return res.status(400).json({ error: 'Email already registered' });
        }

        const customerId = 'CUST' + Math.floor(100000 + Math.random() * 900000);
        const hashedPassword = await bcrypt.hash(password, 10);

        const insertQuery = `
            INSERT INTO CUSTOMER (Customer_ID, First_Name, Last_Name, Phone, Email, Password) 
            VALUES (?, ?, ?, ?, ?, ?)
        `;
        
        await db.promise().query(insertQuery, [customerId, firstName, lastName, phone, email, hashedPassword]);
        res.status(201).json({ message: 'Account successfully created!', customerId });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Internal server registration error' });
    }
});

// 2. SIGN-IN / AUTHENTICATION ROUTE
app.post('/api/signin', async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ error: 'Email and password are required' });
    }

    try {
        const [users] = await db.promise().query('SELECT * FROM CUSTOMER WHERE Email = ?', [email]);
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

// 3. LIVE INVENTORY SYNC ROUTE
app.get('/api/products', async (req, res) => {
    try {
        // Query the database
        const [rows] = await db.promise().query('SELECT * FROM product');
        
        if (rows.length > 0) {
            // MAP the database columns to the keys your frontend expects
            const formattedProducts = rows.map(p => ({
                id: p.Product_ID || p.id,
                name: p.Name || p.name,
                category: (p.Category || p.category || 'Women').toLowerCase(), // Ensure this matches 'women'/'men'
                detail: p.Detail || p.detail || p.Description,
                price: p.Price || p.price,
                // Robust casing fallback chain prevents 'undefined' items from getting stripped
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

const PORT = 5000;
app.listen(PORT, () => {
    console.log(`Backend server running live on http://localhost:${PORT}`);
});