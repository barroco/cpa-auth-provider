"use strict";

var generate = require('../lib/generate');
var request = require('request');

module.exports = function(app) {

  /**
   * Server status endpoint
   */

  var serverOrigin = 'http://local.ebu.io:8090';


  app.post('/tv/register', function(req, res) {
    var client_id = req.cookies.client_id;
    if (client_id) {
      res.json({'client_id': client_id });
      return;
    }

    var registrationBody = {
      client_name: 'tv flow test',
      software_id: 'tv-flow',
      software_version: '0.1'
    };

    var registerUrl = serverOrigin + '/register';
    var registerRequest = {
      url: registerUrl,
      json: registrationBody
    };

    request.post(registerRequest, function(err, httpResponse, body) {
      if (err) {
        return console.error('upload failed:', err);
      }

      client_id = body.client_id;
      var client_secret = body.client_secret;

      if(httpResponse.statusCode !== 201) {
        console.log(httpResponse, body);
        res.send(500);
        return;
      }
      res.cookie('client_id', client_id, { expires: new Date(Date.now() + 900000), httpOnly: true });
      res.cookie('client_secret', client_secret, { expires: new Date(Date.now() + 900000), httpOnly: true });
      res.json({'client_id': client_id });
    });
  });

  app.post('/tv/token', function(req, res) {
    var clientId = req.cookies.client_id;
    var clientSecret = req.cookies.client_secret;
    if (!clientId || req.body.client_id != clientId && !clientSecret) {
      res.json(401, {'reason': 'bad_request'});
      return;
    }

    var registerUrl = serverOrigin + '/token';
    var registerRequest = {
      url: registerUrl,
      json: {
        grant_type: 'http://tech.ebu.ch/cpa/1.0/client_credentials',
        client_id: clientId,
        client_secret: clientSecret,
        domain: 'http://local.ebu.io:8000/'
      }
    };

    request.post(registerRequest, function(err, httpResponse, body) {
      if (err || httpResponse.statusCode !== 200) {
        res.send(400);
        return;
      }

      res.json(body);
    });
  });

  app.get('/tv/token', function(req, res) {
    console.log('AP Cookie: ' + req.cookies.client_id);
    var client_id = req.cookies.client_id;
    var client_secret = req.cookies.client_secret;
    if (!client_id || !client_secret) {
      res.send(401);
      return;
    }

    res.send(200);
  });

};
