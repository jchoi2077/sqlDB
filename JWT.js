const { sign, verify } = require('jsonwebtoken')
const dotenv = require('dotenv').config({ path: './.env'})

const createTokens = (user) => {
    const accessToken = sign({ username: user[0].username, id: user[0].id }, process.env.S_KEY)
    return accessToken;
}

const validateToken = (req, res, next) => {
    const accessToken = req.cookies["access-token"]

    if (!accessToken) {
        return res.status({ error: "User Not Authenticated." })
    }

    try {
        const validToken = verify(accessToken, process.env.S_KEY)
        if (validToken) {
            req.authenticated = true
            return next();
        }
    } catch (err) {
        return res.status(400).json({ error: err })
    }

}


module.exports = { createTokens, validateToken }