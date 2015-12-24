var express = require('express');
var app = express();
var passport = require('passport');
var session = require('express-session');
var KerberosStrategy = require('../lib/index').Strategy;
var cookieParser = require('cookie-parser');

app.use(express.static('public'));
app.use(cookieParser());
app.use(session({
    secret: 'kerberos-secret',
    resave: false,
    saveUninitialized: true
}));
app.use(passport.initialize());
app.use(passport.session());

passport.use(new KerberosStrategy({
        spn: 'SPN',
        keytab: 'KEYTAB'
    }
));

passport.serializeUser(function(user, done) {
    done(null, user);
});

passport.deserializeUser(function(user, done) {
    done(null, user);
});

app.get('/', passport.authenticate('kerberos', {}),
    function (req, res) {
        res.send('This is the main page! (user is ' + req.user + ')');
    });


console.log('listening on port 3000');
app.listen(3000);
