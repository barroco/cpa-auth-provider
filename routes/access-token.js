"use strict";

var config   = require('../config');
var cors     = require('../lib/cors');
var db       = require('../models');
var generate = require('../lib/generate');

var clientMode    = require('./token/client-mode');
var userMode      = require('./token/user-mode');
var webServerFlow = require('./token/webserver-flow');
var refreshToken  = require('./token/refresh-token');

var async = require('async');

var routes = function(app) {

  /**
   * Access token endpoint
   *
   * @see EBU Tech 3366, section 8.3
   */

  var handler = function(req, res, next) {
    if (!req.body.hasOwnProperty('grant_type')) {
      res.sendErrorResponse(400, 'invalid_request', 'Missing grant type');
      return;
    }

    var grantType = req.body.grant_type;

    switch (grantType) {
      // see EBU Tech 3366, section 8.3.1.1 and 8.3.1.3
      case 'http://tech.ebu.ch/cpa/1.0/client_credentials':
        return clientMode(req, res, next);

      // see EBU Tech 3366, section 8.3.1.2
      case 'http://tech.ebu.ch/cpa/1.0/device_code':
        return userMode(req, res, next);

      case 'http://tech.ebu.ch/cpa/1.0/authorization_code':
        return webServerFlow(req, res, next);

      case 'http://tech.ebu.ch/cpa/1.0/refresh_token':
        return refreshToken(req, res, next);

      default:
        return res.sendErrorResponse(
          400,
          'invalid_request',
          "Unsupported grant type: " + grantType
        );
    }
  };

  if (config.cors && config.cors.enabled) {
    // Enable pre-flight CORS request for POST /token
    app.options('/token', cors);
    app.post('/token', cors, handler);
  }
  else {
    app.post('/token', handler);
  }

};

module.exports = routes;
