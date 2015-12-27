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
        spn: 'sys_nbflow',
        keytab: '/nfs/iil/home/nambar/work/tmp/nbflow.keytab3'
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
        res.send('<H1>Welcome to NodeJS Kerberos authentication module!</H1><H3>I bet that you\'re <span style="color:red">' + req.user + '</span></H3>');
    });

var server = app.listen(3002, function () {
    var port = server.address().port;

    console.log('Example server listening at port %s', port);
});