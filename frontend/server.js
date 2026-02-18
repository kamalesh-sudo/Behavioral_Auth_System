
// server.js
const express = require('express');
const path = require('path');

const app = express();
const port = 3000;

// Serve static files
app.use('/dashboard', express.static(path.join(__dirname, 'dashboard')));
app.use('/collector', express.static(path.join(__dirname, 'collector')));
app.use('/login', express.static(path.join(__dirname, 'login')));
app.use('/calibration', express.static(path.join(__dirname, 'calibration')));

// Redirect root to login
app.get('/', (req, res) => {
    res.redirect('/login/login.html');
});

app.listen(port, () => {
    console.log(`Dashboard server listening at http://localhost:${port}`);
});
