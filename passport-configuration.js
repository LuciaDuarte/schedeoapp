'use strict';
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;

const User = require('./models/user');
const bcryptjs = require('bcryptjs');
const nodemailer = require('nodemailer');

const createRandomToken = () => {
  const characters =
    '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
  let token = '';
  for (let i = 0; i < 15; i++) {
    token += characters[Math.floor(Math.random() * characters.length)];
  }
  return token;
};

passport.serializeUser((user, callback) => {
  callback(null, user._id);
});

passport.deserializeUser((id, callback) => {
  User.findById(id)
    .then(user => {
      callback(null, user);
    })
    .catch(error => {
      callback(error);
    });
});

passport.use(
  'local-sign-up',
  new LocalStrategy(
    {
      usernameField: 'email',
      passwordField: 'password',
      passReqToCallback: true
    },
    (req, username, password, callback) => {
      const name = req.body.name;
      const saltRounds = 10;
      const salt = bcryptjs.genSaltSync(saltRounds);
      const hash = bcryptjs.hashSync(password, salt);
      User.create({
        name,
        email: username,
        passwordHash: hash,
        token: createRandomToken()
      })
        .then(user => {
          callback(null, user);
        })
        .catch(error => {
          callback(error);
        });
    }
  )
);

passport.use(
  'local-sign-in',
  new LocalStrategy(
    { usernameField: 'email', passwordField: 'password' },
    (username, password, done) => {
      User.findOne({
        email: username
      })
        .then(user => {
          if (!user) {
            return done(null, false, { message: 'Incorrect username' });
          }

          if (!bcryptjs.compareSync(password, user.passwordHash)) {
            return done(null, false, { message: 'Incorrect password' });
          }

          done(null, user);
        })
        .catch(error => {
          done(error);
        });
    }
  )
);
