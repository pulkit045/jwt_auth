const JWT = require('jsonwebtoken')
const createError = require('http-errors')

module.exports = {
    signAccessToken: (userId) => {
        return new Promise((resovle, reject)=>{
            const payload = {
            }
            const secret = process.env.ACCESS_TOKEN_SECRET
            const options = {
                expiresIn: '1h',
                issuer: 'https://pulkit045.github.io/Portfolio-Website/',
                audience: userId,
            }

            JWT.sign(payload,secret,options,(err, token)=>{
                if(err) return reject(createError.InternalServerError())
                resovle(token)
            })
        })
    },
    verifyAccessToken: (req,res,next) => {
        if(!req.headers['authorization']) return next(createError.Unauthorized())
        const token = req.headers['authorization'].split(' ')[1]
        JWT.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, payload)=>{
            if(err){
                const message = err.name==='JsonWebTokenError' ? 'Unauthorized' : err.message
                return next(createError.Unauthorized(message))
            }
            req.payload = payload
            next()
        })
    },
    signRefreshToken: (userId) => {
        return new Promise((resolve, reject) => {
            const payload = {}
            const secret = process.env.REFRESH_TOKEN_SECRET
            const options = {
                expiresIn: "1y",
                audience: userId,
                issuer: 'https://pulkit045.github.io/Portfolio-Website/',
            }

            JWT.sign(payload, secret, options, (err, token) => {
                if(err) return reject(createError.InternalServerError())
                resolve(token)
            })
        })
    },
    verifyRefreshToken: (refreshToken) => {
        return new Promise((resolve, reject) => {
            JWT.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, (err, payload) => {
                if(err) return reject(createError.Unauthorized())
                const userId = payload.aud
                resolve(userId)
            })
        })
    }
}