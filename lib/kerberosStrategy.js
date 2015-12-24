var passport = require('passport-strategy')
var util = require('util')
var lookup = require('./utils').lookup
var log = require('winston');
var sh = require('child_process');

var gssAuth = __dirname + '/' + '../bin/gss-auth';

function Strategy(options) {
    if (!options.keytab) {
        throw new Error('KerberosStrategy required option keytab is missing');
    }
    if (!options.spn) {
        throw new Error('KerberosStrategy required option spn is missing');
    }
    this._spn = options.spn;
    this._keytab = options.keytab;

    passport.Strategy.call(this);

    this.name = 'kerberos';
}

util.inherits(Strategy, passport.Strategy);

Strategy.prototype.authenticate = function(req, options) {
    options = options || {};

    var authorization = req.headers['authorization'];
    if (!authorization) { return this.fail(this._challenge()); }
    var authData = authorization.split(' ',2);

    if(authData[0] !== 'Negotiate') {
        return this.fail({ message: options.badRequestMessage || 'Got invalid auth header' }, 400);
    }
    var token = authData[1];
    log.debug('auth token: ' + token);
    var cmd =  gssAuth + ' --token ' + token + ' --spn ' + this._spn + ' --keytab ' + this._keytab;
    log.debug('running command: ' + cmd);
    var result = sh.exec(cmd);
    log.debug('output is: ' + result);

    try {
        var user = sh.execSync(cmd);
        log.debug('output is: ' + result);
        this.success('nambar');
    } catch (ex) {
        log.error('auth fail: ' + ex);
        return this.error(ex);
    }
};

Strategy.prototype._challenge = function() {
    return 'Negotiate';
};

module.exports = Strategy;