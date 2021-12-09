require('dotenv').config();
const jwt = require('jsonwebtoken');
const moment = require('moment');
const randtoken = require('rand-token');
const ms = require('ms');


const dev = `${process.env.NODE_ENV}` !== 'production';

const refreshTokens = {};

const COOKIE_OPTIONS = {
    httpOnly: true,
    secure: !dev,
    signed: true
};

function generateToken(user){
    if(!user) return null;

    const u = {
        userId: user.userId,
        name: user.name,
        username: user.username,
        isAdmin: user.isAdmin,
    };

    const xsrfToken = randtoken.generate(24);
    const privateKey = `${process.env.JWT_SECRET}` + xsrfToken;
    const token = jwt.sign(u, privateKey, {expiresIn : 60 * 60 * 24});

    const expiredAt = moment().add(ms(`${process.env.ACCESS_TOKEN_LIFE}`), 'ms').valueOf();

    return {
        token,
        expiredAt,
        xsrfToken
    }
}

function generateRefreshToken(userId){
    if(!userId) return null;

    return jwt.sign({userId}, `${process.env.JWT_SECRET}`, {expiresIn: "30d"});
}

function verifyToken(token, xsrfToken = '', cb){
    const privateKey = `${process.env.JWT_SECRET}` + xsrfToken;
    jwt.verify(token, privateKey, cb);
}

function getCleanUser(user){
    if(!user) return null;

    return {
        userId: user.userId,
        name: user.name,
        username: user.username,
        isAdmin: user.isAdmin,
    };
}

function handleResponse(req, res, statusCode, data, message){
    let isError = false;
    let errorMessage = message;

    switch (statusCode) {
        case 204: 
            return res.sendStatus(204);
        case 400:
            isError = true;
            break;
        case 401: 
            isError = true;
            errorMessage = message || 'Invalid User';
            clearTokens(req, res);
            break;
        case 403: 
            isError = true;
            errorMessage = message || 'Access to this page is denied';
            clearTokens(req, res);
            break;
        default:
            break;
    }

    const resObj = data || {};
    if(isError) {
        resObj.error = true;
        resObj.message = errorMessage;
    }
    return res.status(statusCode).json(resObj);
}



function clearTokens(req, res) {
    const { signedCookies = {} } = req;
    const { refreshToken } = signedCookies;

    delete refreshTokens[refreshToken];
    res.clearCookie('XSRF-TOKEN');
    res.clearCookie('refreshToken', COOKIE_OPTIONS);
}

module.exports = {
    refreshTokens,
    COOKIE_OPTIONS,
    generateToken,
    generateRefreshToken,
    verifyToken,
    getCleanUser,
    handleResponse,
    clearTokens
}