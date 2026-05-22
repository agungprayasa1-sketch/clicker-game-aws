const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');

const app = express();
app.use(express.json());
app.use(express.static('public'));

const SECRET_KEY = 'rahasia_sistem_advisor'; 
const db = new sqlite3.Database('./game.db');
db.serialize(() => {
    db.run("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT, clicks INTEGER DEFAULT 0)");
});
const authenticate = (req, res, next) => {
    const token = req.headers.authorization;
    if (!token) return res.status(401).json({ error: "Akses ditolak" });
    try {
        const decoded = jwt.verify(token, SECRET_KEY);
        req.user = decoded;
        next();
    } catch (err) {
        res.status(401).json({ error: "Token tidak valid" });
    }
};

app.post('/register', (req, res) => {
    const { username, password } = req.body;
    const hash = bcrypt.hashSync(password, 10);
    db.run("INSERT INTO users (username, password) VALUES (?, ?)", [username, hash], function(err) {
        if (err) return res.status(400).json({ error: "Username sudah digunakan" });
        res.json({ message: "Registrasi berhasil" });
    });
});
app.post('/login', (req, res) => {
    const { username, password } = req.body;
    db.get("SELECT * FROM users WHERE username = ?", [username], (err, user) => {
        if (!user || !bcrypt.compareSync(password, user.password)) {
            return res.status(401).json({ error: "Kredensial salah" });
        }
        const token = jwt.sign({ id: user.id, username: user.username }, SECRET_KEY);
        res.json({ token, clicks: user.clicks });
    });
});

app.post('/click', authenticate, (req, res) => {
    db.run("UPDATE users SET clicks = clicks + 1 WHERE id = ?", [req.user.id], function(err) {
        db.get("SELECT clicks FROM users WHERE id = ?", [req.user.id], (err, row) => {
            res.json({ clicks: row.clicks });
        });
    });
});
app.get('/leaderboard', (req, res) => {
    db.all("SELECT username, clicks FROM users ORDER BY clicks DESC LIMIT 10", [], (err, rows) => {
        res.json(rows);
    });
});
app.listen(3000, () => console.log('Server beroperasi di Port 3000'));