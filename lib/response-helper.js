"use strict";

var querystring = require('querystring');

module.exports = function(logger) {

  /**
   * Sends an error HTTP response, with the given status code and a response
   * body containing a JSON object with the error identifier and description.
   * If redirectUri is provided, the error is send in the query component
   * of the redirection URI using the "application/x-www-form-urlencoded" format.
   * See [RFC6749, 4.1.2.1.  Error Response]
   */

  var sendErrorResponse = function(status, error, description) {
    logger.debug(description);
    this.send(status, { error: error, error_description: description });
  };


  var redirectImplicitError = function(redirectUri, error, description, state) {
    logger.debug(description);

    var query = {
      error: error,
      error_description: description,
      state: state
    };

    var destinationUri = redirectUri + '#' + querystring.stringify(query);
    this.redirect(destinationUri);
  };

  var redirectError = function(redirectUri, error, description, state) {
    logger.debug(description);

    var query = {
      error: error,
      error_description: description,
      state: state
    };

    var destinationUri = redirectUri + '?' + querystring.stringify(query);
    this.redirect(destinationUri);
  };

  var sendInvalidRequest = function(description) {
    this.sendErrorResponse(400, 'invalid_request', description);
  };

  var sendInvalidClient = function(description) {
    this.sendErrorResponse(400, 'invalid_client', description);
  };

  var sendUnauthorized = function(description) {
    this.sendErrorResponse(401, 'unauthorized', description);
  };

  /**
   * Expess middleware function that adds helper methods to the response
   * object (res), for sending error repsonses.
   */

  var responseHelper = function(req, res, next) {
    res.redirectImplicitError  = redirectImplicitError.bind(res);
    res.redirectError          = redirectError.bind(res);
    res.sendErrorResponse      = sendErrorResponse.bind(res);
    res.sendInvalidClient      = sendInvalidClient.bind(res);
    res.sendInvalidRequest     = sendInvalidRequest.bind(res);
    res.sendUnauthorized       = sendUnauthorized.bind(res);
    next();
  };

  return responseHelper;
};
