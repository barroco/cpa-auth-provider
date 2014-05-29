"use strict";

var async = require('async');
var url = require('url');

var db = require('../models');
var authHelper = require('../lib/auth-helper');
var generate = require('../lib/generate');
var querystring = require('querystring');

var schemaGet = {
  id: "/authorize",
  type: "object",
  required: true,
  additionalProperties: false,
  properties: {
    response_type: {
      type: "string",
      required: true
    },
    client_id: {
      type: "string",
      required: true
    },
    redirect_uri: {
      type: "string",
      required: true
    },
    scope: {
      type:     "string",
      required: false
    },
    state: {
      type:     "string",
      required: false
    }
  }
};

var schemaPost = {
  id: "/authorize",
  type: "object",
  required: true,
  additionalProperties: false,
  properties: {
    response_type: {
      type: "string",
      required: true
    },
    client_id: {
      type: "string",
      required: true
    },
    redirect_uri: {
      type: "string",
      required: true
    },
    scope: {
      type:     "string",
      required: false
    },
    state: {
      type:     "string",
      required: false
    },
    domain: {
      type:     "string",
      required: true
    },
    authorization: {
      type:     "string",
      required: true
    }
  }
};

var validateUri = require('../lib/validate-json').validate;
var validatePostBody = require('../lib/validate-form')(schemaPost);

module.exports = function(app, options) {

  /**
   * Access token authorization endpoint
   */

  app.get('/authorize',
    authHelper.authenticateFirst,
    function(req, res, next) {

    var responseType = req.query.response_type;
    var clientId     = req.query.client_id;
    var redirectUri  = req.query.redirect_uri;
    var domain       = req.query.domain;
    var state        = req.query.state;

    if (responseType !== 'code' && responseType !== 'token') {
      res.sendInvalidRequest('Invalid response_type');
      return;
    }

    var redirectErrorHandler = (responseType === 'token') ?
      res.redirectImplicitError : res.redirectError;

    if (!req.query.hasOwnProperty('client_id')) {
      res.sendInvalidRequest('Missing client_id');
      return;
    }

    if (!req.query.hasOwnProperty('redirect_uri')) {
      res.sendInvalidRequest('Missing redirect_uri');
      return;
    }

    db.Client
      .find({ where: { id: clientId } })
      .complete(function(err, client) {
        if(err || !client) {
          res.sendInvalidClient('Unknown client');
          return;
        }
        if ((responseType == 'code' && client.registration_type === 'dynamic') ||
          (responseType == 'token' && !client.redirect_uri)) {
          res.sendErrorResponse(400, 'unauthorized_client',
            'The client is not authorized to request ' +
            'an authorization code using this method');
          return;
        }
        if (client.redirect_uri !== redirectUri) {
          res.sendInvalidClient('Unauthorized redirect uri');
          return;
        }

        var validationError = validateUri(req.query, schemaGet);
        if (!validationError) {
          if (responseType !== 'code' && responseType !== 'token') {
            redirectErrorHandler(client.redirect_uri, 'unsupported_response_type',
              "Wrong response type: 'code' or 'token' required.");
            return;
          }

          res.render('authorize.ejs', {
            response_type: responseType,
            client_name: client.name,
            client_id: clientId,
            redirect_uri: redirectUri,
            domain: domain,
            state: state,
            error: null
          });
        }
        else {
          redirectErrorHandler(client.redirect_uri, 'invalid_request',
            validationError);
        }
      });
  });

  app.post('/authorize', validatePostBody, authHelper.ensureAuthenticated,
    function(req, res, next) {

      //TODO: Verify valid informations
      var responseType  = req.body.response_type;
      var clientId      = req.body.client_id;
      var userId        = req.user.id;
      var redirectUri   = req.body.redirect_uri;
      var domainName    = req.body.domain;
      var state         = req.body.state;
      var authorization = req.body.authorization;
      var redirectErrorHandler = (responseType === 'token') ?
        res.redirectImplicitError : res.redirectError;

      var userAuthorizationCheck = function(callback) {
        if (authorization !== 'Allow') {
          return redirectErrorHandler(redirectUri,
            'access_denied',
            'The resource owner or authorization server denied the request.',
            state);
        }
        callback();
      };

      var validateClient = function(callback) {
        db.Client
          .find({ where: { id: clientId } })
          .complete(function(err, client) {
            if (err || !client) {
              res.sendInvalidClient('Unknown client');
              return;
            }
            if ((responseType == 'code' && client.registration_type === 'dynamic') ||
              (responseType == 'token' && !client.redirect_uri)) {
              res.sendErrorResponse(400, 'unauthorized_client',
                  'The client is not authorized to request ' +
                  'an authorization code using this method');
              return;
            }
            if (client.redirect_uri !== redirectUri) {
              res.sendInvalidClient('Unauthorized redirect uri');
              return;
            }
            callback(null, client);
          });
      };

      var findDomain = function(client, callback) {
        db.Domain.find({ where: { name: domainName }})
          .complete(function(err, domain) {
            if (err || !domain) {
              redirectErrorHandler(client.redirect_uri, 'Invalid domain');
              return;
            }
            callback(null, domain);
          });
      };

      // Generate Authorization code
      var createAuthorizationCode = function(domain, callback) {
        var authorizationCode = {
          client_id:          clientId,
          domain_id:          domain.id,
          redirect_uri:       redirectUri,
          user_id:            userId,
          authorization_code: generate.authorizationCode()
        };

        db.AuthorizationCode.create(authorizationCode)
          .complete(callback);
      };

      var createAccessToken = function(domain, callback) {
        db.sequelize.transaction(function(transaction) {
          var accessToken = {
            token:     generate.accessToken(),
            domain_id:    domain.id,
            user_id:   userId,
            client_id: clientId
          };

          db.AccessToken
            .create(accessToken)
            .then(function() {
              return transaction.commit();
            })
            .then(function() {
              callback(null, accessToken, domain);
            },
            function(error) {
              transaction.rollback().complete(function(err) {
                callback(err);
              });
            });
        });
      };

      var handleCodeRequest = function() {
        async.waterfall([
            userAuthorizationCheck,
            validateClient,
            findDomain,
            createAuthorizationCode
          ],
          function (err, result) {
            if (err) {
              next(err);
              return;
            }

            var urlObj = url.parse(redirectUri);
            if (!urlObj.query) {
              urlObj.query = {};
            }
            urlObj.query.code = result.authorization_code;
            urlObj.query.state = state;

            res.redirect(url.format(urlObj));
          });
      };

      var handleTokenRequest = function() {
        async.waterfall([
            userAuthorizationCheck,
            validateClient,
            findDomain,
            createAccessToken
          ],
          function (err, accessToken, domain) {
            if (err) {
              next(err);
              return;
            }

            var urlObj = url.parse(redirectUri);
            urlObj.hash = querystring.stringify({
              access_token: accessToken.token,
              token_type:   'bearer',
              expires_in:   '',
              domain:       domain.name
            });

            res.redirect(url.format(urlObj));
          });
        return;
      };

      if (responseType !== 'code' && responseType !== 'token') {
        res.sendInvalidRequest('Invalid response_type');
        return;
      }

      if (responseType === 'code') {
        handleCodeRequest();
        return;
      }

      if (responseType === 'token') {
        handleTokenRequest();
        return;
      }

      res.send(400);
  });
};
