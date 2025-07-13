'use strict';

const express               = require('express');
const router                = express.Router();
const bcrypt                = require('bcryptjs');
const generator             = require('generate-password');
const jwt                   = require('jsonwebtoken');
const { isPrimitiveNumber } = require('conjunction-junction');
const { 
  JWT_SECRET,
  JWT_EXPIRY, 
  authFile }               = require('../config/_main');
const logger               = require('log123').createLogger(authFile);
const { 
  handleAttemptedHack,
  sendPwReset }            = require('../comm/notifications');
const { respondToError }   = require('../comm/responses');
const knex                 = require('../db-sql');
const { 
  getIpAddr,
  hasSql }                 = require('../helpers/_security');

router.use(express.json());

const userFields = ['id', 'first_name', 'last_name', 'permissions', 'email'];

const hashPassword = password => {
  return bcrypt.hash(password, 12);
};

const validatePassword = (suppliedPW, userPW) => {
  return bcrypt.compare(suppliedPW, userPW);
};

const createAuthToken = user => {
  return jwt.sign(
    {user},      // object to encrypt
    JWT_SECRET,
    {            // object has a fixed format; do not edit (subject can be another string)
      subject: user.username,
      expiresIn: JWT_EXPIRY,
      algorithm: 'HS256'
    }
  );
};

const userIsAdmin = userContainer => {
  return userContainer && 
  userContainer.contents &&
  userContainer.contents.user &&
  Array.isArray(userContainer.contents.user.permissions) &&
    userContainer.contents.user.permissions.includes('admin');
};

const getUserPermissions = userContainer => {
  return userContainer && 
  userContainer.contents.user &&
  userContainer.contents.user &&
  Array.isArray(userContainer.contents.user.permissions) ?
    userContainer.contents.user.permissions :
    [];
};

const routesAllowed = {
  GET: {
    user: { // most basic permissions

    },
    admin: {
      '//api/users/*': true,
    },
  },
  POST: {
    user: {
      '//api/auth/relogin': true,
    },
    admin: {
      '//api/users': true,
    },
  },
  PUT: {
    user: {
      '//api/users/*/pw': true,
    },
    admin: {
      '//api/users/*': true,
    }
  },
  DELETE: {
    admin: {

    },
  },
};

// add all urls to admin
for(let method in routesAllowed){
  for(let permission in routesAllowed[method]){
    if(permission !== 'admin'){
      for(let url in routesAllowed[method][permission]){
        if(!routesAllowed[method].admin[url]){
          routesAllowed[method].admin[url] = true;
        }
      }
    }
  }
}

const jwtStrategy = (req, res, next, userContainer={})=>{
  // this is middleware, so don't throw (it won't make it back to the calling function)
  // instead respond on error, and the calling function is never called
  // see next() at the end, which calls the calling function if this passes
  // step 1: check header or url parameters or post parameters for token
  var tokenWithBearer = req.headers.authorization;
  if(!tokenWithBearer){
    res.status(403).json({
      message:'No Token'
    });
  } else {
    const token = tokenWithBearer.slice(7,tokenWithBearer.length);
    
    // Decode the token
    jwt.verify(token,JWT_SECRET,(err,decod)=>{
      // console.log('err', err, 'decod', decod);


      if(err){
        res.status(403).json({message:'Wrong Token'});
      } else {
        //If decoded then call next() so that respective route is called.
        req.decoded = decod;
        // console.log(decod)
        // we must APPEND userContainer
        // trying to replace it does not work
        userContainer.contents = req.decoded;
        if(!Array.isArray(req.decoded.user.permissions)){
          res.status(403).json({
            message:`Cannot read permissions for ${req.decoded.user.username}`,
          });
        } else {
          if(req.decoded.exp < req.decoded.iat) {
            res.status(403).json({
              message:'Expired Token'
            });
          } else if(!routesAllowed[req.method]) {
            res.status(403).json({
              message:`Sorry, ${req.method} access not granted to you, ${req.decoded.user.username}`
            });
          } else {
            const urlOnly = req.originalUrl.split('?')[0];
            const urlArray = urlOnly.split('/');
            const urlArrayAdjusted = urlArray.map(u=>{
              // const iString = `${i}`;
              const asInt = parseInt(u, 10);
              const isNum = isPrimitiveNumber(asInt);
              const segment =
                u === '' ? '/' :
                  isNum && `${asInt}` === `${u}` ? '*' : u;
              return segment;
            });

            const url = urlArrayAdjusted.join('/');
            // console.log(url)
            const allowedPermission = userContainer.contents.user.permissions.find(p=>{
              // console.log('p',p, 'routesAllowed[req.method][p]',routesAllowed[req.method][p])
              if(routesAllowed[req.method][p] &&
                routesAllowed[req.method][p][url]){
                return true;
              }
            });
            // console.log(allowedPermission)
            if(!allowedPermission) {
              res.status(403).json({
                message:`Sorry, ${req.method} access to ${req.originalUrl} not granted to you, ${req.decoded.user.username}, permissions: ${userContainer.contents.user.permissions}`
              });
            } else {
              // console.log('ALLOWED', userContainer.contents.user, req.method, req.originalUrl)
              next();
            }
          } // end if expired / else if no routes found / else check allowedPath
        }   // end if no permissions / else permissions
      }     // end if err / else no err
    });     // end verify token function
  }         // end if no token / else token
};

router.post('/login', (req, res) => {
  const ip = getIpAddr(req);
  const bodyWithoutToken = Object.assign({},req.body,{authToken:null});
  const foundHack = hasSql(bodyWithoutToken)||hasSql(req.params.path)||hasSql(req.query);
  if(foundHack){
    return handleAttemptedHack('POST/api/auth/login',req,res,ip,foundHack);
  }

  let authToken, userFound;
  const userFromClient = req.body;
  if(!userFromClient.username) {
    // all responses are 200 so that we control the message being sent back
    res.status(200).json({ message: 'missing username' });
    return;
  } else if(!userFromClient.password){
    res.status(200).json({ message: `missing password for ${userFromClient.username}` });
    return;
  } else {
    const rawSql = `select ${userFields.join(', ')} from users where username = '${userFromClient.username.toLowerCase()}';`;
    return knex.raw(rawSql)
      .then(found => {
        const users = Array.isArray(found.rows) ? found.rows : [] ;
        if(users.length <= 0) {
          return res.status(200).json({ message: `user ${userFromClient.username} not found` });
        }
        userFound = users[0];
        // console.log(userFound)
        return validatePassword(userFromClient.password, userFound.password);
      })
      .then( isValid => {
        if(!userFound){
          return; // already responded
        }
        if(!isValid) {
          return res.status(200).json({ message: `incorrect password for ${userFromClient.username}` });
        } else {
          const userForToken = {
            id:          userFound.id,
            username:    userFound.username,
            permissions: userFound.permissions,
          };
          authToken = createAuthToken(userForToken);
          const userForResponse = {
            id:          userFound.id,
            username:    userFound.username,
            firstName:   userFound.first_name,
            lastName:    userFound.last_name,
            authToken:   authToken,
            pwReset:     userFound.pw_reset,
            permissions: userFound.permissions,
          };
          return res.status(200).json(userForResponse);
        }
      })
      .catch(err => {
        respondToError(err, res);
      });
  }
});

router.post('/relogin', (req, res) => {
  const ip = getIpAddr(req);
  const bodyWithoutToken = Object.assign({},req.body,{authToken:null});
  const foundHack = hasSql(bodyWithoutToken)||hasSql(req.params.path)||hasSql(req.query);
  if(foundHack){
    return handleAttemptedHack('POST/api/auth/relogin',req,res,ip,foundHack);
  }
  
  const authToken = req.body.authToken;
  let idUser = null;

  if(authToken){
    return new Promise(resolve=>{
      resolve(
        jwt.verify(authToken,JWT_SECRET,(err,decod)=>{
          if(!err && decod.user && isPrimitiveNumber(decod.user.id)){
            idUser = decod.user.id;
          }
        })
      );
    })
      .then(()=>{
        if(idUser){
          const rawSql = `select id, username, permissions, first_name, last_name from users where id = ${idUser};`;
          return knex.raw(rawSql)
            .then(found => {
              const userFound = found && found.rows && found.rows[0] ? found.rows[0] : null ; 
              if(!userFound){
                throw {message: 'user not found'};
              }
              const userForToken = {
                id:          userFound.id,
                username:    userFound.username,
                permissions: userFound.permissions,
              };
              const newAuthToken = createAuthToken(userForToken);
              const userForResponse = {
                id:          userFound.id,
                username:    userFound.username,
                firstName:   userFound.firstName,
                lastName:    userFound.lastName,
                authToken:   newAuthToken,
                permissions: userFound.permissions,
              };
              // logger.info('userForResponse',userForResponse);
              return userForResponse;
            })
            .then(user => {
              // logger.info('user',user);
              return res.status(200).json(user);
            })
            .catch(err => {
              respondToError(err, res);
            });
        }
        // logger.info('should only see this if no idUser');
        return res.status(400).json({message: 'invalid request'});
      });
  }
  logger.info('user has no token');
  return res.status(400).json({message: 'missing auth token, cannot reauthenticate; please log in with username and password'});
});

router.post('/pwreset', (req, res) => {
  const ip = getIpAddr(req);
  const bodyWithoutToken = Object.assign({},req.body,{authToken:null});
  const foundHack = hasSql(bodyWithoutToken)||hasSql(req.params.path)||hasSql(req.query);
  if(foundHack){
    return handleAttemptedHack('POST/api/auth/pwreset',req,res,ip,foundHack);
  }
  
  let tempPw;
  const email = req.body ? req.body.email : null;
  if(!email || typeof email !== 'string') {
    return res.status(400).json({message: 'invalid email'});
  }
  return knex('users')
    .where('email', '=',  email.toLowerCase())
    .then( usersFound => { 
      return usersFound[0];
    })
    .then(user => {
      const id = user ? user.id : null ;
      if(id){
        tempPw = generator.generate({
          length: 10,
          numbers: true
        });
        if(process.env.NODE_ENV === 'test'){
          console.log(tempPw);
        }
        return hashPassword(tempPw)
          .then(hashed=>{
            return knex('users')
              .update({
                password: hashed,
                pw_reset: true,
              })
              .where('id', '=',  id)
              .then(usersFound => { 
                return usersFound[0];
              });
          })
          .then(()=>{
            sendPwReset(user, tempPw);
            // console.log(tempPw)
            const responseObject = {
              error: false,
              message: `We sent the username and temporary password to ${user.email}. Use those credentials to log in above, then reset your password.`
            };
            res.status(200).json(responseObject);
          });
      } else {
        const responseObject = {
          error: true,
          message: `We did not find the user ${email}`,
        };
        // status 400 or 401 does not return our custom message...
        res.status(200).json(responseObject);
      }
    })
    .catch( err => {
      respondToError(err, res);
    });
});

module.exports = {
  router, 
  jwtStrategy, 
  hashPassword,
  createAuthToken,
  userIsAdmin,
  getUserPermissions,
};