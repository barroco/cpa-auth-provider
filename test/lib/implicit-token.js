"use strict";

var db       = require('../../models');
var generate = require('../../lib/generate');

var assertions    = require('../assertions');
var requestHelper = require('../request-helper');

var async   = require('async');
var cheerio = require('cheerio');
var url     = require('url');
var querystring = require('querystring');

var clearDatabase = function(done) {
  db.sequelize.query('DELETE FROM Domains').then(function() {
    return db.sequelize.query('DELETE FROM Clients');
  })
  .then(function() {
    return db.sequelize.query('DELETE FROM AccessTokens');
  })
  .then(function() {
    return db.sequelize.query('DELETE FROM Users');
  })
  .then(function() {
    done();
  },
  function(error) {
    done(new Error(JSON.stringify(error)));
  });
};

var createCorrectClient = function(callback) {
  db.Client
    .create({
      id:               100,
      secret:           'e2412cd1-f010-4514-acab-c8af59e5501a',
      name:             'Test client',
      software_id:      'CPA AP Test',
      software_version: '0.0.1',
      ip:               '127.0.0.1',
      redirect_uri:     'http://example.com/implicit-client.html'
    }).complete(callback);
};

var createClientWithoutRedirectUri = function(callback) {
  db.Client
    .create({
      id:               101,
      secret:           'e2412cd1-f010-4514-acab-c8af59e5501a',
      name:             'Test client',
      software_id:      'CPA AP Test',
      software_version: '0.0.1',
      ip:               '127.0.0.1'
    }).complete(callback);
};

var createDomain = function(callback) {
  db.Domain.create({
    id:           5,
    name:         'example-service.bbc.co.uk',
    display_name: 'BBC Radio',
    access_token: '70fc2cbe54a749c38da34b6a02e8dfbd'
  }).complete(callback);
};

var createUser = function(callback) {
  db.User.create({
    id: '25',
    provider_uid: 'testuser',
    password: 'testpassword'
  }).complete(callback);
};

var initDatabase = function(done) {
  async.series([
    createCorrectClient,
    createClientWithoutRedirectUri,
    createUser,
    createDomain
  ], function(err) {
      if(err){
        done(new Error(JSON.stringify(err)));
        return;
      }
      done();
    });
};

var getFragment = function(location) {
  var hash = url.parse(location).hash.substr(1);
  hash = querystring.parse(hash);
  return hash;
};

var removeFragment = function(href) {
  return href.substring(0, href.indexOf('#'));
};

describe('POST /authorize [Implicit Flow]', function() {
  before(function() {
    sinon.stub(generate, 'accessToken').returns('aed201ffb4462de42700a293bdebf694');
  });

  after(function() {
    generate.accessToken.restore();
  });

  context("when the client redirects the resource owner for authorization", function() {
    before(clearDatabase);
    before(initDatabase);

    context('when user is authenticated', function() {
      before(function(done) {
        var self = this;

        request
          .post('/login')
          .type('form')
          .send({ username: 'testuser', password: 'testpassword' })
          .end(function(err, res) {
            self.cookie = res.headers['set-cookie'];
            done(err);
          });
      });

      context('and click on the Allow button', function() {
        context('with valid parameters in the form', function() {
          before(function(done) {

            var formData = {
              response_type: 'token',
              client_id:     '100',
              redirect_uri:  'http://example.com/implicit-client.html',
              domain:        'example-service.bbc.co.uk',
              state:         '',
              authorization: 'Allow'
            };

            requestHelper.sendRequest(this, '/authorize', {
              method: 'post',
              type: 'form',
              cookie: this.cookie,
              data: formData
            }, done);
          });

          it('should reply with a status code 302', function() {
            expect(this.res.statusCode).to.equal(302);
          });

          it('should contain a location header', function() {
            expect(this.res.headers).to.have.property('location');
          });

          describe('the location header', function() {
            it('should contain absolute url with a fragment', function() {
              var location = url.parse(this.res.headers.location);
              expect(location).to.have.property('protocol');
              expect(location.protocol.length).to.be.greaterThan(0);
              expect(location.hash.length).to.be.greaterThan(0);
            });

            it('should contain the redirect url', function() {
              var location = url.parse(this.res.headers.location);
              expect(removeFragment(location.href)).to.equal('http://example.com/implicit-client.html');
            });

            describe('the fragment', function() {
              it('should contain access_token', function() {
                var hash = getFragment(this.res.headers.location);
                expect(hash).to.have.property('access_token');
                expect(hash.access_token).to.equal('aed201ffb4462de42700a293bdebf694');
              });

              it('should contain token_type', function() {
                var hash = getFragment(this.res.headers.location);
                expect(hash).to.have.property('token_type');
                expect(hash.token_type).to.equal('bearer');
              });

              it('should contain domain', function() {
                var hash = getFragment(this.res.headers.location);
                expect(hash).to.have.property('domain');
                expect(hash.domain).to.equal('example-service.bbc.co.uk');
              });

              it("should include the lifetime of the access token"); // TODO: recommended: expires_in
            });
          });

          describe("the database", function() {
            before(function(done) {
              var self = this;

              db.AccessToken.findAll()
                .then(function(accessTokens) {
                  self.accessTokens = accessTokens;
                  done();
                },
                function(error) {
                  done(error);
                });
            });

            it("should contain a new access token", function() {
              // jshint expr: true
              expect(this.accessTokens).to.be.ok;
              expect(this.accessTokens).to.be.an('array');
              expect(this.accessTokens.length).to.equal(1);
            });

            describe("the access token", function() {
              it("should have correct value", function() {
                expect(this.accessTokens[0].token).to.equal('aed201ffb4462de42700a293bdebf694');
              });

              it("should be associated with the correct client", function() {
                expect(this.accessTokens[0].client_id).to.equal(100);
              });

              it("should not be associated with a user", function() {
                expect(this.accessTokens[0].user_id).to.equal(25);
              });

              it("should be associated with the correct domain", function() {
                expect(this.accessTokens[0].domain_id).to.equal(5);
              });
            });
          });
        });

        context('with client_id of a client registered without redirect_uri', function() {
          before(function(done) {

            var formData = {
              response_type: 'token',
              client_id:     '101',
              redirect_uri:  'http://example.com/implicit-client.html',
              domain:        'example-service.bbc.co.uk',
              state:         '',
              authorization: 'Allow'
            };

            requestHelper.sendRequest(this, '/authorize', {
              method: 'post',
              type:   'form',
              cookie: this.cookie,
              data:   formData
            }, done);
          });

          it("should return an unauthorized_client error", function() {
            assertions.verifyError(this.res, 400, 'unauthorized_client');
          });
        });


        context('with missing client_id', function() {
          before(function(done) {
            var formData = {
              response_type: 'token',
              redirect_uri:  'http://example.com/implicit-client.html',
              domain:        'example-service.bbc.co.uk',
              state:         '',
              authorization: 'Allow'
            };

            requestHelper.sendRequest(this, '/authorize', {
              method: 'post',
              type:   'form',
              cookie: this.cookie,
              data:   formData
            }, done);
          });

          it("should return an invalid_request error", function() {
            assertions.verifyError(this.res, 400, 'invalid_request');
          });
        });

        context('with invalid client_id', function() {
          before(function(done) {
            var formData = {
              response_type: 'token',
              client_id:     'in',
              redirect_uri:  'http://example.com/implicit-client.html',
              domain:        'example-service.bbc.co.uk',
              state:         '',
              authorization: 'Allow'
            };

            requestHelper.sendRequest(this, '/authorize', {
              method: 'post',
              type:   'form',
              cookie: this.cookie,
              data:   formData
            }, done);
          });

          it("should return an invalid_client error", function() {
            assertions.verifyError(this.res, 400, 'invalid_client');
          });
        });

        context('with missing response_type', function() {
          before(function(done) {
            var formData = {
              client_id:     '100',
              redirect_uri:  'http://example.com/implicit-client.html',
              domain:        'example-service.bbc.co.uk',
              state:         '',
              authorization: 'Allow'
            };

            requestHelper.sendRequest(this, '/authorize', {
              method: 'post',
              type:   'form',
              cookie: this.cookie,
              data:   formData
            }, done);
          });

          it("should return an invalid_request error", function() {
            assertions.verifyError(this.res, 400, 'invalid_request');
          });
        });

        context('with invalid response_type', function() {
          before(function(done) {
            var formData = {
              response_type: 'device',
              client_id:     '100',
              redirect_uri:  'http://example.com/implicit-client.html',
              domain:        'example-service.bbc.co.uk',
              state:         '',
              authorization: 'Allow'
            };

            requestHelper.sendRequest(this, '/authorize', {
              method: 'post',
              type:   'form',
              cookie: this.cookie,
              data:   formData
            }, done);
          });

          it("should return an invalid_request error", function() {
            assertions.verifyError(this.res, 400, 'invalid_request');
          });
        });

        context('with missing redirect_uri', function() {
          before(function(done) {
            var formData = {
              response_type: 'token',
              client_id:     '100',
              domain:        'example-service.bbc.co.uk',
              state:         '',
              authorization: 'Allow'
            };

            requestHelper.sendRequest(this, '/authorize', {
              method: 'post',
              type:   'form',
              cookie: this.cookie,
              data:   formData
            }, done);
          });

          it("should return an invalid_request error", function() {
            assertions.verifyError(this.res, 400, 'invalid_request');
          });
        });

        context('with a different redirect_uri than the client\'s one', function() {
          before(function(done) {
            var formData = {
              response_type: 'token',
              client_id:     '100',
              redirect_uri:  'http://wrong-example.com/implicit-client.html',
              domain:        'example-service.bbc.co.uk',
              state:         '',
              authorization: 'Allow'
            };

            requestHelper.sendRequest(this, '/authorize', {
              method: 'post',
              type:   'form',
              cookie: this.cookie,
              data:   formData
            }, done);
          });

          it("should return an invalid_client error", function() {
            assertions.verifyError(this.res, 400, 'invalid_client');
          });
        });
      });

      context('and click on the Deny button (Valid parameters in form)', function() {
        before(function(done) {
          var formData = {
            response_type: 'token',
            client_id:     '100',
            redirect_uri:  'http://example.com/implicit-client.html',
            domain:        'example-service.bbc.co.uk',
            state:         '',
            authorization: 'Deny'
          };

          requestHelper.sendRequest(this, '/authorize', {
            method: 'post',
            type:   'form',
            cookie: this.cookie,
            data:   formData
          }, done);
        });

        it('should reply an access_denied error', function() {
          assertions.verifyImplicitError(this.res, 'access_denied');
        });
      });
    });
  });
});
