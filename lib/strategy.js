/**
 * Module dependencies.
 */
var passport = require('passport-strategy')
  , util = require('util');


/**
 * Creates an instance of `Strategy`.
 *
 * The HTTP Bearer authentication strategy authenticates requests based on
 * a bearer token contained in the `Authorization` header field, `access_token`
 * body parameter, or `access_token` query parameter.
 *
 * Applications must supply a `verify` callback, for which the function
 * signature is:
 *
 *     function(token, done) { ... }
 *
 * `token` is the bearer token provided as a credential.  The verify callback
 * is responsible for finding the user who posesses the token, and invoking
 * `done` with the following arguments:
 *
 *     done(err, user, info);
 *
 * If the token is not valid, `user` should be set to `false` to indicate an
 * authentication failure.  Additional token `info` can optionally be passed as
 * a third argument, which will be set by Passport at `req.authInfo`, where it
 * can be used by later middleware for access control.  This is typically used
 * to pass any scope associated with the token.
 *
 * Options:
 *
 *   - `scope`  list of scope values indicating the required scope of the access
 *              token for accessing the requested resource
 *
 * Examples:
 *
 *     passport.use(new BearerStrategy(
 *       function(token, done) {
 *         User.findByToken({ token: token }, function (err, user) {
 *           if (err) { return done(err); }
 *           if (!user) { return done(null, false); }
 *           return done(null, user, { scope: 'read' });
 *         });
 *       }
 *     ));
 *
 * For further details on HTTP Bearer authentication, refer to [The OAuth 2.0 Authorization Protocol: Bearer Tokens](http://tools.ietf.org/html/draft-ietf-oauth-v2-bearer)
 *
 * @constructor
 * @param {Object} [options]
 * @param {Function} verify
 * @api public
 */
function Strategy(options, verify) {
  if (typeof options == 'function') {
    verify = options;
    options = {};
  }
  if (!verify) { throw new TypeError('HTTPBearerStrategy requires a verify callback'); }

  passport.Strategy.call(this);
  this.name = 'bearer';
  this._verify = verify;
  if (options.scope) {
    this._scope = (Array.isArray(options.scope)) ? options.scope : [ options.scope ];
  }
  this._passReqToCallback = options.passReqToCallback;
}

/**
 * Inherit from `passport.Strategy`.
 */
util.inherits(Strategy, passport.Strategy);

/**
 * Authenticate request based on the contents of a HTTP Bearer authorization
 * header, body parameter, or query parameter.
 *
 * @param {Object} req
 * @api protected
 */
Strategy.prototype.authenticate = function(req) {
  var token;

  if (req.headers && req.headers.authorization) {
    var authHeader = req.headers.authorization;

    /* Temporary fix - remove 15 May 2014 */
    /* A bug in the OSX client adds this header each time a refresh is done */
    if(authHeader.indexOf('Bearer ') === 0 && authHeader.indexOf(',') >= 0) {
      authHeader = authHeader.split(/,/)[0];
    }

    var parts = authHeader.split(' ');
    if (parts.length == 2) {
      var scheme = parts[0]
        , credentials = parts[1];

      if (/^Bearer$/i.test(scheme)) {
        token = credentials;
      }
    } else {
      return this.fail(400);
    }
  }

  if (req.headers && req.headers['x-access-token']) {
    var accessTokenHeader = req.headers['x-access-token'];
    if (token && accessTokenHeader !== token) { return this.fail(400); }

    token = accessTokenHeader;
  }

  if (req.query && req.query.access_token) {
    var queryToken = req.query.access_token;
    if (token && queryToken !== token) { return this.fail(400); }
    token = queryToken;
  }

  if (!token) { return this.fail(401); }

  var self = this;

  function verified(err, user, info) {
    if (err) { return self.error(err); }
    if (!user) {
      if (typeof info == 'string') {
        info = { message: info };
      }
      info = info || {};
      return self.fail(401);
    }
    self.success(user, info);
  }

  if (self._passReqToCallback) {
    this._verify(req, token, verified);
  } else {
    this._verify(token, verified);
  }
};

/**
 * Expose `Strategy`.
 */
module.exports = Strategy;
