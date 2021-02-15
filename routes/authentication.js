'use strict';

const { Router } = require('express');
const passport = require('passport');
const router = new Router();

router.get('/sign-up', (req, res) => {
  res.render('auth/sign-up');
});

router.post(
  '/sign-up',
  passport.authenticate('local-sign-up', {
    successRedirect: '/',
    failureRedirect: '/authentication/sign-in'
  })
);

router.get('/sign-in', (req, res) => {
  res.render('auth/sign-in');
});

router.post('/sign-in', (req, res, next) => {
  passport.authenticate('local-sign-in', (err, theUser, failureDetails) => {
    if (err) {
      // Something went wrong authenticating user
      return next(err);
    }

    if (!theUser) {
      console.log(failureDetails);
      // Unauthorized, `failureDetails` contains the error messages from our logic in "LocalStrategy" {message: '…'}.
      res.render('auth/sign-in', {
        errorMessage: failureDetails.message
      });
      return;
    }

    req.login(theUser, error => {
      if (error) {
        // Session save went bad
        return next(error);
      }

      res.redirect('/');
    });
  })(req, res, next);
});

// router.post(
//   '/sign-in',
//   passport.authenticate('local-sign-in', {
//     successRedirect: '/',
//     failureRedirect: '/authentication/sign-in'
//   })
// );

router.get('/:id/sign-up', (req, res) => {
  res.render('auth/sign-up-display');
});

router.post(
  '/:id/sign-up',
  passport.authenticate('local-sign-up', {
    failureRedirect: '/authentication/sign-in'
  }),
  (req, res) => {
    const id = req.params.id;
    res.redirect(`/event/${id}/join`);
  }
);

router.get('/:id/sign-in', (req, res) => {
  res.render('auth/sign-in-display');
});

router.post('/:id/sign-in', (req, res, next) => {
  passport.authenticate('local-sign-in', (err, theUser, failureDetails) => {
    if (err) {
      // Something went wrong authenticating user
      return next(err);
    }

    if (!theUser) {
      // Unauthorized, `failureDetails` contains the error messages from our logic in "LocalStrategy" {message: '…'}.
      res.render('auth/sign-in-display', {
        errorMessage: failureDetails.message
      });
      return;
    }

    req.login(theUser, error => {
      if (error) {
        // Session save went bad
        return next(error);
      }

      const id = req.params.id;
      res.redirect(`/event/${id}/join`);

      //  res.redirect('/');
    });
  })(req, res, next);
});

// router.post(
//   '/:id/sign-in',
//   passport.authenticate('local-sign-in', {
//     failureRedirect: '/sign-in'
//   }),
//   (req, res) => {
//     const id = req.params.id;
//     res.redirect(`/event/${id}/join`);
//   }
// );

router.post('/sign-out', (req, res) => {
  req.logout();
  res.redirect('/');
});

module.exports = router;
