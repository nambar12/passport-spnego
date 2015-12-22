/* example from> https://github.com/jaredhanson/passport-local/tree/master/lib */
/**
 * Module dependencies.
 */
var passport = require('passport-strategy')
    , util = require('util')
    , lookup = require('./utils').lookup
    , exec = require('child_process').exec;

//var gssAuth = '../bin/gss-auth';
var gssAuth = '../bin/convertToken2username.pl';

/**
 * `Strategy` constructor.
 *
 * The kerberos authentication strategy authenticates requests based on the
 * KDC token included in req.
 *
 * Applications must supply a `verify` callback which accepts `token`
 * and then calls the `done` callback supplying a
 * `user`, which should be set to `false` if the token is not valid.
 * If an exception occured, `err` should be set.
 *
 * Optionally, `options` can be used to change the fields in which the
 * token is found.
 *
 * Options:
 *   - `kerberosToken`  field name where the kerberos token is found
 *   - `passReqToCallback`  when `true`, `req` is the first argument to the verify callback (default: `false`)
 *
 * Examples:
 *
 *     passport.use(new KerberosStrategy(
 *       function(kerberosToken, done) {
 *         if (req.user) {
 *         done(err, req.user);
 *         }
 *       }
 *     ));
 *
 * @param {Object} options
 * @param {Function} verify
 * @api public
 */
function Strategy(options, verify) {
    if (typeof options == 'function') {
        verify = options;
        options = {};
    }
    if (!verify) { throw new TypeError('KerberosStrategy requires a verify callback'); }

    this.spn = options.spn || undefined;
    this.keytab = options.keytab || undefined;

    passport.Strategy.call(this);

    this.name = 'kerberos';
    this._verify = verify;
    this._passReqToCallback = options.passReqToCallback;
}

/**
 * Inherit from `passport.Strategy`.
 * Inherit from `passport.Strategy`.
 */
util.inherits(Strategy, passport.Strategy);

/**
 * Authenticate request based on the contents of a form submission.
 *
 * @param {Object} req
 * @api protected
 */
Strategy.prototype.authenticate = function(req, options) {
    options = options || {};
    console.log('req.headers.authorization--------------- ' + req.headers.authorization);
    var token = ' --token ' + (req.headers.authorization !== undefined ? req.headers.authorization.replace(/^Negotiate /, '') : '');
    var spn = ' --spn ' + this.spn;
    var keytab = ' --keytab ' + this.keytab;

    if (!token) {
        return this.fail({ message: options.badRequestMessage || 'Missing kerberos token in request' }, 400);
    }
    if (!spn || !keytab) {
        return this.fail({ message: optiopns.badOptionsMessage || 'Missing either spn or keytab or both in options'}, 400 );
    }

    /*
     * --spn in options
     * --keytab in options
     * --token in request
     * --verbose
     */
    var gssAuthArguments = ' ' + spn + keytab + token + ' ';
    var gssAuthCommand = __dirname + '/' + gssAuth + gssAuthArguments;
    //../bin/gss-auth --spn sys_gras --keytab /nfs/site/home/nambar/work/tmp/gras.keytab --token YIIanwYGKw
    console.log('dirpath: ' + __dirname);
    console.log('Command: ' + __dirname + '/' + gssAuthCommand);
    exec(gssAuthCommand, function (error, stdout, stderr) {
        console.log('gss-auth error: ' + error);
        console.log('gss-auth stdout:' + stdout);
        console.log('gss-auth stderr:' + stderr);
    });

    var self = this;

    function verified(err, user, info) {
        if (err) { return self.error(err); }
        if (!user) { return self.fail(info); }
        self.success(user, info);
    }

    try {
        if (self._passReqToCallback) {
            this._verify(req, token, verified);
        } else {
            this._verify(token, verified);
        }
    } catch (ex) {
        return self.error(ex);
    }
};


/**
 * Export `Strategy`.
 */
module.exports = Strategy;