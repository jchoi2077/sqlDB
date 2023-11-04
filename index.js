const express = require('express');
const app = express();
const mysql = require('mysql2/promise')
const bcrypt = require('bcrypt')
const cookieParser = require('cookie-parser')
const { createTokens, validateToken } = require('./JWT')

const dotenv = require('dotenv').config({ path: './.env'})



const PORT = 3500;

app.use(express.json())
app.use(cookieParser())


const db = mysql.createPool({
    host: process.env.HOST,
    user: process.env.USER,
    password: process.env.PWD,
    database: process.env.DB
})

const insertSql = 'INSERT INTO user (username, password) VALUES (?, ?)';
const selectSql = 'SELECT * FROM user WHERE username = ?';


app.post('/register', async (req, res) => {
    const { username, password } = req.body;
    const hashPwd = await bcrypt.hash(password, 10);

    db.query(insertSql, [username, hashPwd]).then(() => {
        res.json('User Registered')
    }).catch((err) => {
        if (err) {
            res.status(400).json({ error: "User Already Exists" })
        }
    })
})


app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    const [user] = await db.query(selectSql, [username]);
    
    if (user.length === 0) {
        res.status(400).json({ error: "User Doesn't Exist" })
    }

    const dbPwd = user[0] ? user[0].password : null;
    bcrypt.compare(password, dbPwd).then((match) => {
        if (!match) {
            res.status(400).json({ error: "Wrong User/Pass" })
        } else {
            const accessToken = createTokens(user)
            res.cookie('access-token', accessToken, {
                maxAge: 60*60*24*30*1000,
                httpOnly: true,
            })

            res.json('Logged In')
        }
    })
})  



app.get('/profile', validateToken, (req, res) => {
    res.json('profile')
})


app.listen(PORT, () => {
    console.log('Running on 3500')
}) 