var request = require('request');

var SAASPASS_API_BASE_URL = "https://www.saaspass.com/sd/rest/applications/";

function SaasPass(options) {
  if (!(this instanceof SaasPass)) {
    return new SaasPass(options);
  }

  options = options || {};

  if (!options.key) {
    throw new Error("API key required");
  }

  var apiKey = options.key;
  var apiToken = options.token;
  var apiBaseUrl = SAASPASS_API_BASE_URL + apiKey;

  var sp = {};
  var proto = this;

  //authenticate our application with SaasPass and get a new token
  sp.authenticate = function(password, callback) {    
    if (password == null) {
      return callback(new Error("Password required"));
    }
    
    request({
      baseUrl: apiBaseUrl,
      url: '/tokens',
      qs: {
        password: password
      }
    }, function(error, response, body) {
       if(!error && response.statusCode === 200) {
         //successfully authenticated
         apiToken = JSON.parse(body).token;
         callback(null, apiToken);
       } else {
         callback(error || proto.apiError(response));
       }
    });
  };

  sp.checkOtp = function(username, otp, callback) {
    if(!apiToken) {
      return callback(new Error("checkOtp requires authentication"));
    }
    if(username == null) {
      return callback(new Error("Username required"));
    }
    if(otp == null) {
      return callback(new Error("OTP required"));
    }
    request({
      baseUrl: apiBaseUrl,
      url: '/otpchecks',
      qs: {
        otp: otp,
        username: username,
        token: apiToken
      }
    }, function (error, response, body) {
      if (!error && response.statusCode == 200) {
	callback(null, true);
      } else {
        callback(error || proto.apiError(response));
      }
    });
  };

  return sp;  
}

//create an Error object from the api error information in the response body
SaasPass.prototype.apiError = function(response) {
  if(response.statusCode === 400) return new Error("API Error. Bad Request");
  var err = new Error("Unknown Error")
  try {
    var details = JSON.parse(response.body);
    err = new Error(details.message);
    err.name = details.name;
  } catch(e) {}
  return err;
};


module.exports = SaasPass;
