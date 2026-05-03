const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bodyParser = require('body-parser');
const path = require('path');
const session = require('express-session');

const app = express();
const db = new sqlite3.Database('./users.db');

app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(session({ secret: 'secretKey', resave: false, saveUninitialized: true }));

// Serve file statici (CSS, JS, immagini) dalla cartella static
app.use('/static', express.static(path.join(__dirname, 'static')));

// LOGIN
app.post('/login', (req, res) => {
    const { username, password } = req.body;
    db.get('SELECT * FROM users WHERE username = ? AND password = ?', [username, password], (err, user) => {
        if (err) return res.status(500).send('Errore server');
        if (!user) return res.status(401).send('Username o password errati');

        req.session.user = { id: user.id, username: user.username, role: user.role };
        res.json({ role: user.role });
    });
});

// CREA SLOT (solo admin)
app.post('/create-slot', (req, res) => {
    if (!req.session.user || req.session.user.role !== 'admin') return res.status(403).send('Accesso negato');
    const { date, time, max_people } = req.body;
    db.run('INSERT INTO slots (date, time, max_people) VALUES (?, ?, ?)', [date, time, max_people || 15], function (err) {
        if (err) return res.status(500).send('Errore server');
        res.json({ success: true, id: this.lastID });
    });
});

// LISTA SLOT DISPONIBILI (user)
app.get('/slots', (req, res) => {
    db.all(`SELECT s.*, 
        (SELECT COUNT(*) FROM bookings b WHERE b.slot_id = s.id) AS booked
        FROM slots s`, [], (err, rows) => {
        if (err) return res.status(500).send('Errore server');
        res.json(rows);
    });
});

// PRENOTA SLOT (user)
app.post('/book', (req, res) => {
    if (!req.session.user || req.session.user.role !== 'user') return res.status(403).send('Accesso negato');
    const userId = req.session.user.id;
    const { slot_id } = req.body;

    db.get('SELECT max_people, (SELECT COUNT(*) FROM bookings WHERE slot_id = ?) AS booked FROM slots WHERE id = ?', [slot_id, slot_id], (err, slot) => {
        if (err) return res.status(500).send('Errore server');
        if (!slot) return res.status(404).send('Slot non trovato');
        if (slot.booked >= slot.max_people) return res.status(400).send('Slot pieno');

        db.get('SELECT * FROM bookings WHERE slot_id = ? AND user_id = ?', [slot_id, userId], (err, exists) => {
            if (exists) return res.status(400).send('Hai già prenotato questo slot');

            db.run('INSERT INTO bookings (slot_id, user_id) VALUES (?, ?)', [slot_id, userId], function (err) {
                if (err) return res.status(500).send('Errore server');
                res.json({ success: true, bookingId: this.lastID });
            });
        });
    });
});

// LOGOUT
app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/template/login.html'); // <-- ora punta alla cartella template
});

// ROUTE PER SERVIRE LE PAGINE
app.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname, 'template', 'login.html'));
});
app.get('/admin', (req, res) => {
    res.sendFile(path.join(__dirname, 'template', 'admin.html'));
});
app.get('/user', (req, res) => {
    res.sendFile(path.join(__dirname, 'template', 'user.html'));
});

// START SERVER
app.listen(3000, () => console.log('Server avviato su http://localhost:3000'));