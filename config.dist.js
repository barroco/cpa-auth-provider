"use strict";

exports.passport = {
//Details : http://passportjs.org/guide/facebook/
  FACEBOOK_CLIENT_ID: 0,
  FACEBOOK_CLIENT_SECRET: '',
  FACEBOOK_CALLBACK_URL: ''
};

exports.db = {
  host: '',
  port: 3306,
  user: '',
  password: '',
  type: '',
  database: '',
  filename: '' // database filename for sqlite
};


exports.uris = {
  registration_client_uri: '',

  // The end-user verification URI on the authorization server. The URI should
  // be short and easy to remember as end-users will be asked to manually type
  // it into their user-agent.
  verification_uri: ''
};

exports.realm = 'CPA';
