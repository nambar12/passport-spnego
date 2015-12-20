'use strict';

process.on('uncaughtException', function (error) {
    console.log(error.stack);
});

var pkg = require('../package.json');
var exec = require('child_process').exec;
var winston = require('./util/logger.js');
var express = require('express');
var session = require('express-session');
var cookieParser = require('cookie-parser');
var url = require('url');
var bodyParser   = require( 'body-parser' );
var passport = require('passport');
var SamlStrategy = require( 'passport-saml' ).Strategy;
var Q = require('q');
var app = express();
var server;

winston.log('info','Main:: Starting server ' + pkg.version );
if (process.env.NODE_ENV) {
    winston.log('info','Main:: NODE_ENV =  ' + process.env.NODE_ENV);
}

// this function is called when you want the server to die gracefully
// i.e. wait for existing connections
function gracefulShutdown() {
    winston.log('info','Received kill signal, shutting down gracefully.');
    server.close(function() {
        winston.log('Closed out remaining connections.');
        process.exit();
    });

    // if after
    setTimeout(function() {
        winston.log('error','Could not close connections in time, forcefully shutting down');
        process.exit();
    }, 10*1000);
}

app.use(session({
    secret: 'keyboard cat',
    resave: false,
    saveUninitialized: true
}));
app.use(cookieParser());
app.use(passport.initialize());
app.use(passport.session());

passport.use(new SamlStrategy(
    {
        path: '/login/callback',
        entryPoint: 'https://intel.oktapreview.com/app/template_saml_2_0/k2p2jrwgZQCTBBBZUZVY/sso/saml',
        //entryPoint: 'https://openidp.feide.no/simplesaml/saml2/idp/SSOService.php',
        issuer: 'passport-saml'
    },
    function(profile, done) {
        if(profile.email === 'nambar@gmail.com') {
            return done(null, profile);
        }
        return done(null, "aaa");
    })
);

passport.serializeUser(function(user, done) {
    done(null, user);
});

passport.deserializeUser(function(user, done) {
    done(null, user);
});

app.use(bodyParser.urlencoded({extended: false}));
app.use(bodyParser.json());

function validateParam(param) {
    //if (!(preg_match ('/^[A-Za-z0-9-.]+:[0-9]+$/', $session))) {
    return true;
}

function doExec(cmd, res) {
    exec(cmd, function (error, stdout, stderr) {
        console.log('stdout: ' + stdout);
        console.log('stderr: ' + stderr);
        if (error !== null) {
            console.log('exec error: ' + error);
            res.json( { error : error} );
        } else {
            res.json(stdout.split('\n'));
        }
    });

}

app.post('/login/callback',
    passport.authenticate('saml', { failureRedirect: '/', failureFlash: true }),
    function(req, res) {
        res.redirect('/');
    }
);

app.get('/',
    passport.authenticate('saml', { failureRedirect: '/', failureFlash: true }),
    function(req, res) {
        res.redirect('/');
    }
);

app.use(express.static(__dirname + '/../dist/vnc'));

app.all('/api/*', function(req, res, next) {
    res.header('Access-Control-Allow-Origin', '*');
    res.header('Access-Control-Allow-Credentials', true);
    res.header('Access-Control-Allow-Methods', 'POST, GET, PUT, DELETE, OPTIONS');
    res.header('Access-Control-Allow-Headers', "X-Requested-With, Content-Type");
    next();
});

app.get('/api/user', function(req,res) {
    //res.json(req.user);
    res.json('nambar');
});

app.get('/api/vncserver', function(req,res) {
    //var cmd = '/usr/bin/sudo -H -u ' + req.user.user + ' /usr/intel/bin/vnclist';
    var cmd = 'cmd /c dir /B';
    doExec(cmd, res);
});

app.delete('/api/vncserver', function(req,res) {
    // var session = url.parse(request.url, true).query.session;
    validateParam(session);
    // var cmd = '/usr/bin/sudo -H -u ' + req.user.user + ' /usr/intel/bin/vncstop ' . session;
    var cmd = 'cmd /c dir /B';
    doExec(cmd, res);
});

app.post('/api/vncserver', function(req,res) {
    validateParam(req.body.geometry);
    var cmd = '/usr/bin/sudo -H -u ' + req.user.user + ' /srv/www/htdocs/vnc/vncstart.sh -geometry ' . req.body.geometry;
    cmd = 'cmd /c dir /B';
    doExec(cmd, res);
});


server = app.listen(3000, function () {
    var host = server.address().address;
    var port = server.address().port;

    winston.log('info','Main:: server running on http://%s:%s', host, port);
});


// listen for TERM signal .e.g. kill
process.on ('SIGTERM', gracefulShutdown);

// listen for INT signal e.g. Ctrl-C
process.on ('SIGINT', gracefulShutdown);


