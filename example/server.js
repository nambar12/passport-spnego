var express = require('express');
var app = express();
var passport = require('passport');
var KerberosStrategy = require('../lib/index').Strategy;


app.get('/a', function (req, res) {
    res.send('Hello World - a');
//    console.log('response:', res);
    console.log('request:', req.headers);
});

app.get('/login', function (req, res) {
    res.send('Hello World - login');
//    console.log('response:', res);
    console.log('request:', req.headers);
});


var success = function () {
    console.log('Success');
}

app.post('/login', passport.authenticate('kerberos',
    {
        successRedirect: success,
        failureRedirect: '/loginfail'
    })
);

app.get('/loginfail', function(req, res){
    res.json(401, {message: 'Invalid login details'});
});

passport.serializeUser(function(user, done) {
    done(null, user.id);
});

passport.deserializeUser(function(id, done) {
    User.findById(id, function(err, user) {
        done(err, user);
    });
});

passport.use(new KerberosStrategy({
        spn: 'SPN',
        keytab: 'KEYTAB'
    },
    function(token, done) {
        console.log('new KerberosStrategy, token:' + token);
        console.log('new KerberosStrategy, done:' + done);
    }
));

//passport.authenticate('kerberos');

console.log('listening on port 3000');
app.listen(3000);
