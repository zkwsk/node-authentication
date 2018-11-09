var express = require('express');
var router = express.Router();
var expressValidator = require('express-validator');
var passport = require('passport');

var bcrypt = require('bcrypt');
const saltRounds = 10;

router.get('/', function(req, res, next) {
  console.log(req.user);
  console.log(req.isAuthenticated());
  res.render('home', { title: 'Home' });
})
router.get('/profile', authenticationMiddleware(), function(req, res) {
  res.render('profile', { title: 'Profile' });
})
router.post('/login', passport.authenticate('local',
  {
    successRedirect: '/profile',
    failureRedirect: '/login'
  }
));
router.get('/login', function(req, res) {
  res.render('login', { title: 'Login' });
});
router.get('/logout', function(req, res) {
  req.logout();
  req.session.destroy();
  res.redirect('/');
});
router.get('/register', function(req, res, next) {
  res.render('register', { title: 'Registration' });
});
router.post('/register', function(req, res, next) {

  // Validation

  // Username
  req.checkBody('username', 'Username field cannot be empty.').notEmpty();
  req.checkBody('username', 'Username must be between 4-15 characters long.').len(4, 15);
  req.checkBody('username', 'Username can only contain letters, numbers, or underscores.')
    .matches(/^[A-Za-z0-9_-]+$/, 'i');
  
  // Email
  req.checkBody('email', 'Email is not valid.').isEmail();
  req.checkBody('email', 'Email address must be between 4 and 255 characters long.').len(4, 255);

  // Password
  req.checkBody('password', 'Password must be between 8-100 characters long').len(8, 100);
  //req.checkBody('password', 'Password must include one lowercase character, one uppercase character, a number, and a special character.')
  //  .matches(/^(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?!.* )(?=.*[^a-zA-Z0-9]).{8,}$/, "i");
  
  // Password match
  req.checkBody('passwordMatch', 'Password must be between 8-100 characters long.').len(8, 100);
  req.checkBody('passwordMatch', 'Passwords do not match, please try again.').equals(req.body.password);

  const errors = req.validationErrors();

  if (errors) {
    console.log(`errors: ${JSON.stringify(errors)}`);
    res.render('register', { title: 'Registration error', errors: errors });
  } else {
    const { username, email, password } = req.body;
    const db = require('../db.js');
  
    bcrypt.hash(password, saltRounds, function(err, hash) {
      db.query('INSERT INTO users (username, email, password) VALUES (?, ?, ?)', [username, email, hash], 
        function(error, results, fields) {
  
        if (error) throw error;
    
        db.query('SELECT LAST_INSERT_ID() as user_id', function(error, results, fields) {
          if (error) throw error;

          const user_id = results[0];

          req.login(user_id, function(err) {
            if (err) throw err;
            res.redirect('/');
          });

          res.render('register', { title: 'Registration Complete' });
        });
        
      });
    });
  }
});

passport.serializeUser(function(user_id, done) {
  console.log('serializing');
  done(null, user_id);
});

passport.deserializeUser(function(user_id, done) {
  done(null, user_id);
});

function authenticationMiddleware () {  
	return (req, res, next) => {
		console.log(`req.session.passport.user: ${JSON.stringify(req.session.passport)}`);

	    if (req.isAuthenticated()) return next();
	    res.redirect('/login')
	}
}

module.exports = router;
