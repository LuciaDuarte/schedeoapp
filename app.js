'use strict';

const { join } = require('path');
const express = require('express');
const createError = require('http-errors');
const cookieParser = require('cookie-parser');
const logger = require('morgan');
const mongoose = require('mongoose');
const sassMiddleware = require('node-sass-middleware');
const serveFavicon = require('serve-favicon');
const hbs = require('hbs');

const helperDate = require('helper-date');
const helperJson = require('hbs-json');

const session = require('express-session');
const MongoStore = require('connect-mongo')(session);

//const bcrypt = require('bcrypt');
const passport = require('passport');
//const LocalStrategy = require('passport-local').Strategy;

const bindUserToViewLocals = require('./middleware/bind-user-to-view-locals.js');

const app = express();

app.set('views', join(__dirname, 'views'));
app.set('view engine', 'hbs');

hbs.registerPartials(join(__dirname, 'views/partials'));
hbs.registerHelper('dateHelper', helperDate);
hbs.registerHelper('helperJson', helperJson);

app.use(serveFavicon(join(__dirname, 'public/images', 'calendar.png')));
app.use(
  sassMiddleware({
    src: join(__dirname, 'public'),
    dest: join(__dirname, 'public'),
    outputStyle:
      process.env.NODE_ENV === 'development' ? 'nested' : 'compressed',
    force: process.env.NODE_ENV === 'development',
    sourceMap: true
  })
);
app.use(express.static(join(__dirname, 'public')));
app.use(logger('dev'));
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: true,
    saveUninitialized: false,
    cookie: {
      maxAge: 60 * 60 * 24 * 15,
      sameSite: 'lax',
      httpOnly: true
      //secure: process.env.NODE_ENV === "production",
    },
    store: new MongoStore({
      mongooseConnection: mongoose.connection,
      ttl: 60 * 60 * 24
    })
  })
);
require('./passport-configuration');

app.use(passport.initialize());
app.use(passport.session());
app.use(bindUserToViewLocals);

app.locals.appUrl = process.env.APP_URL;

const indexRouter = require('./routes/index');
const eventRouter = require('./routes/event');
const extrasRouter = require('./routes/extras');
const authenticationRouter = require('./routes/authentication');

app.use('/', indexRouter);
app.use('/authentication', authenticationRouter);
app.use('/event', eventRouter);
app.use('/event', extrasRouter);

// Catch missing routes and forward to error handler
app.use((req, res, next) => {
  next(createError(404));
});

// Catch all error handler
app.use((error, req, res, next) => {
  // Set error information, with stack only available in development
  res.locals.message = error.message;
  res.locals.error = req.app.get('env') === 'development' ? error : {};
  res.status(error.status || 500);
  res.render('error');
});

module.exports = app;
