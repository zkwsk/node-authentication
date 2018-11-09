var express = require('express');
var router = express.Router();
var expressValidator = require('express-validator');

var bcrypt = require('bcrypt');
const saltRounds = 10;

router.get('/', function(req, res, next) {
  res.render('home', { title: 'Home' });
})
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
    
        res.render('register', { title: 'Registration Complete' });
      });
    });
  }
});

module.exports = router;
