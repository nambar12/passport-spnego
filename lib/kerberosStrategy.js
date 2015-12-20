/* example from> https://github.com/jaredhanson/passport-local/tree/master/lib */
/**
 * Module dependencies.
 */
var passport = require('passport-strategy')
    , util = require('util')
    , lookup = require('./utils').lookup
    , exec = require('child_process').exec;

var gssAuth = '../bin/convertToken2Username.pl';

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

    this._kerberosToken = options.kerberosToken || '';

    passport.Strategy.call(this);

    this.name = 'kerberos';
    this._verify = verify;
    this._passReqToCallback = options.passReqToCallback;
}

/**
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
    var kerberosToken = lookup(req.body, this._kerberosToken) || lookup(req.query, this._kerberosToken);
    var token = ' --token ' + req.headers.authorization.replace(/^Negotiate /, '');
    var spn = ' --spn ' + options.spn;
    var keytab = ' --keytab ' + options.keytab;
    /*
     * --spn in options
     * --keytab in options
     * --token in request
     * --verbose
     */
    if (spn && keytab) {

        gssAuth = gssAuth + ' ' + spn + keytab + token;
        console.log('Command: ' + gssAuth);
        exec(gssAuth, function (error, stdout, stderr) {
            console.log(stdout);
        });
    }

    if (!kerberosToken) {
        return this.fail({ message: options.badRequestMessage || 'Missing kerberos token in request' }, 400);
    }

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