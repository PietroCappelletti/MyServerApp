if (process.env.NODE_ENV !== 'production') {
    require('dotenv').config()
}

const jwt = require('jsonwebtoken');
const express = require('express');
const bcrypt = require('bcrypt');
const expressLayout = require('express-ejs-layouts');
const bodyParser = require('body-parser');

const indexRouter = require('./routes/index');
const authorsRouter = require('./routes/authors');
const bookRouter = require('./routes/books');

const app = express();
app.set('view engine', 'ejs')
app.set('views', __dirname + '/views')
app.set('layout', 'layouts/layout')
app.use(expressLayout)
app.use(express.static('public'))
app.use(bodyParser.urlencoded({ limit: '10mb', extended: false }))
app.use(express.json());

//Database rappresentation
const users = [];
let refreshTokens = [];

const mongoose = require('mongoose')
mongoose.connect(process.env.DATABASE_URL, { useNewUrlParser: true })
const db = mongoose.connection
db.on('error', error => console.error(error))
db.once('open', () => console.log('Connected to Mongoose'))

app.use('/', indexRouter);
app.use('/authors', authorsRouter);
app.use('/books', bookRouter);

//Require middlewear
    //const { authenticateToken } = require('./middlewear/authenticationToken');


//#region API JWT

app.get('/users', authenticateToken, (req, res) => {
    res.json(users);
    // posts.filter(post => post.username === req.user.name); 
});

app.post('/users/register', async (req, res) => {
    try {
        const hashedPassword = await bcrypt.hash(req.body.password, 10);
        const user = { name: req.body.name, password: hashedPassword };
        users.push(user);
        res.status(201).send(user);
    } catch (error) {
        console.log(error);
        res.status(500).send();
    }
});

app.post('/users/login', async (req, res) => {
    const user = users.find(user => user.name == req.body.name);
    if (user == null) {
        return res.status(400).send('Cannot find user');
    }
    try {
        if(await bcrypt.compare(req.body.password, user.password)) {
            //User has currently logged in
            const accessToken = generateAccessToken(user);
            const refreshToken = jwt.sign(user, process.env.REFRESH_TOKEN_SECRET);
            refreshTokens.push(refreshToken);
            res.json({accessToken: accessToken, refreshToken: refreshToken });
        } else {
            res.send('Not allowed');
        }
    } catch (error) {
        res.status(500).send();
    }
});

app.delete('/users/logout', (req, res) => {
    refreshTokens = refreshTokens.filter(token => token !== req.body.token);
    res.sendStatus(204);
});

app.post('/users/token', (req, res) => {
    const refreshToken = req.body.token;
    
    if (refreshToken == null) return res.sendStatus(401);
    if (!refreshTokens.includes(refreshToken)) return res.sendStatus(403);

    jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);
        const accessToken = generateAccessToken({ name: user.name });
        res.json({ accessToken: accessToken })
    })
});

function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (token == null) return res.sendStatus(401);

    jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
}

function generateAccessToken(user) {
    return jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '20s' });
}

//#endregion


app.listen(process.env.PORT || 3000, () => {
});

/*
    User: {
        username: "username",           UNIQUE
        verified: true/false
        password: "password",
        email: "email@email.com"        UNIQUE
    }
*/