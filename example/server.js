var express = require('express');
var app = express();
var passport = require('passport');
var KerberosStrategy = require('passport-spnego').Strategy;


app.get('/', function (req, res) {
    res.send('Hello World');
    console.log('response:', res);
    console.log('request:', req);
});

app.post('/login', passport.authenticate('kerberos',
    {
        successRedirect: '/',
        failureRedirect: '/login'
    })
);

passport.serializeUser(function(user, done) {
    done(null, user.id);
});

passport.deserializeUser(function(id, done) {
    User.findById(id, function(err, user) {
        done(err, user);
    });
});

passport.use(new KerberosStrategy({
        kerberosToken: ''
    },
    function(token, done) {
        // ...
    }
));


app.listen(3000);