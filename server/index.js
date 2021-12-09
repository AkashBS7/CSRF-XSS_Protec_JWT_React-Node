require('dotenv').config();

const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const {
  refreshTokens, COOKIE_OPTIONS, generateToken, generateRefreshToken,
  getCleanUser, verifyToken, clearTokens, handleResponse,
} = require('./utils');

const userList = [
    {
      userId: "123",
      password: "123456",
      name: "aka",
      username: "ghost",
      isAdmin: true
    },
    {
      userId: "456",
      password: "mediator",
      name: "Mediator",
      username: "mediator",
      isAdmin: true
    },
    {
      userId: "789",
      password: "123456",
      name: "Clue Mediator",
      username: "cluemediator",
      isAdmin: true
    }
  ]

const app = express();
const port = 4000;

app.use(cors({
    origin: 'http://localhost:3000',
    credentials: true
}));

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({extended: true}));

app.use(cookieParser(`${process.env.COOKIE_SECRET}`));

const authMiddleware = function (req, res, next) {
    var token = req.headers['authorization'];
    if(!token) return handleResponse(req, res, 401);
    token = token.replace('Bearer ', '');

    const xsrfToken = req.headers['x-xsrf-token'];
    if(!xsrfToken) return handleResponse(req, res, 403)

    const { signedCookies = {} } = req;
    const { refreshToken } = signedCookies;
    if(!refreshToken || !(refreshToken in refreshTokens) || refreshTokens[refreshToken] !== xsrfToken){
        return handleResponse(req, res, 401);
    }

    verifyToken(token, xsrfToken, (err, payload) => {
        if(err) {
            return handleResponse(req, res, 401);
        }
        else{
            req.user = payload;
            next();
        }
    });
}


app.post('/users/signin', function (req, res) {
    const user = req.body.username;
    const pwd = req.body.password;

    if(!user || !pwd){
        return handleResponse(req, res, 400, null, "Username and Password is required");
    }
    const userData = userList.find(x => x.username === user && x.password === pwd);

    if(!userData){
        return handleResponse(req, res, 401, null, "Username or Password is incorrect");
    }

    const userObj = getCleanUser(userData);
    const tokenObj = generateToken(userData);
    const refreshToken = generateRefreshToken(userObj.userId);

    refreshTokens[refreshToken] = tokenObj.xsrfToken;

    res.cookie('refreshToken', refreshToken, COOKIE_OPTIONS);
    res.cookie('XSRF_TOKEN', tokenObj.xsrfToken);

    return handleResponse(req, res, 200, {
        user: userObj,
        token: tokenObj.token,
        expiresAt: tokenObj.expiredAt
    });
});

app.post('/users/logout', (req, res) => {
    clearTokens(req, res);
    return handleResponse(req, res, 204);
});

app.post('/verifyToken', function (req, res) {
    const { signedCookies = {} } = req;
    const { refreshToken } = signedCookies;
    if(!refreshToken){
        return handleResponse(req, res, 204);
    }

    const xsrfToken = req.headers['x-srf-token'];
    if(!xsrfToken || !(refreshToken in refreshTokens) || refreshTokens[refreshToken] !== xsrfToken){
        return handleResponse(req, res, 401);
    }

    verifyToken(refreshToken, '', (err, payload) => {
        if(err) {
            return handleResponse(req, res, 401);
        } else {
            const userData = userList.find(x => x.userId === payload.userId);
            if(!userData){
                return handleResponse(req, res, 401);
            }

            const userObj = getCleanUser(userData);
            const tokenObj = generateToken(userData);

            refreshTokens[refreshToken] = tokenObj.xsrfToken;
            res.cookie('XSRF_TOKEN', tokenObj.xsrfToken);

            return handleResponse(req, res, 200, {
                user: userObj,
                token: tokenObj.token,
                expiredAt: tokenObj.expiredAt
            });
        }
    });
});

app.get('/users/getlist', authMiddleware, (req, res) => {
    const list = userList.map(x => {
        const user = {...x};
        delete user.password;
        return user;
    });
    return handleResponse(req, res, 200, {random: Math.random(), userList: list});
})




app.listen(port, ()=>{
    console.log(`listening on port ${port}`);
});