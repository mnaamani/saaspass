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
  //will throw an error if password is not provided
  //callback is optional
  sp.authenticate = function(password, callback) {
    if (password == null) {
      throw new Error("Password required");
    }

    callback = callback || function(){};

    request({
      baseUrl: apiBaseUrl,
      url: '/tokens',
      qs: {
        password: password
      }
    }, function(error, response, body) {
       if(error || response.statusCode === 500) return callback(error || new Error("500 Server error"));
       if(response.statusCode === 200) {
         //successfully authenticated
         apiToken = JSON.parse(body).token;
         callback(null, apiToken);
       } else {
         callback(proto.apiError(response));
       }
    });
  };

  sp.OTP = {};
  sp.OTP.verify = function(username, otp, callback) {
    if(typeof callback !== 'function') {
      throw new Error("Callback function required");
    }
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
      if(error || response.statusCode === 500) return callback(error || new Error("500 Server error"));
      if (response.statusCode == 200) {
          callback(null, true);
      } else {
        callback(proto.apiError(response));
      }
    });
  };

  sp.INSTANT = {};
  sp.INSTANT.getBarcodes = function(type, sessionId, callback) {
    if(typeof callback !== 'function') {
      throw new Error("Callback function required");
    }
    if(!apiToken) {
      return callback(new Error("getBarcodeImage requires authentication"));
    }
    //valid instant login/registration strategies
    if(["IL","BT","ILBT", "IR", "ILIR"].indexOf(type) == -1){
        return callback(new Error("Invalid login strategy type"));
    }
    if(sessionId == null) {
      return callback(new Error("session required"));
    }

    request({
      baseUrl: apiBaseUrl,
      url: '/barcodes',
      qs: {
        session: sessionId,
        type: type,
        token: apiToken
      }
    }, function (error, response, body) {
      if(error || response.statusCode === 500) return callback(error || new Error("500 Server error"));
      if (response.statusCode == 200) {
          callback(null, JSON.parse(body));
      } else {
        callback(proto.apiError(response));
      }
    });
  };

  //custom apps will receive instant login notification as post request
  //containing username, tracker, and the sessionId
  //this method verifies that the notification is valid
  sp.TRACKER = {};
  sp.TRACKER.verify = function(username, tracker, sessionId, callback) {
    if(!username || !tracker) {
      return callback(new Error("Invalid tracker request"));
    }

    request({
      baseUrl: apiBaseUrl,
      url: '/trackers/' + tracker,
      qs: {
        account: username,
        token: apiToken
      }
    }, function (error, response, body) {
      if(error || response.statusCode === 500) return callback(error || new Error("500 Server error"));
      if (response.statusCode == 200) {
          callback(null, {
            account: username,
            session: sessionId //if SSO or Widget was used to login this will be undefined
          });
      } else {
        callback(proto.apiError(response));
      }
    });
  };

  //handle POST requests with tracker information which can come from two
  //sources
  //1. SAASPASS servers - if displaying barcode on custom login page
  //2. Through the browser by the SAASPASS login Widget
  sp.TRACKER.handleRequest = function(request, callback) {
    if(!request || !request.body) {
      return callback(new Error("Empty request"));
    }

    if(typeof request.body === 'string') {
      //request should have been parsed by express using body-parser middleware
      return callback(new Error("Reuest not parsed"));
    }

    var info = request.body;

    if(info.session) {
      //POST request from SAASPASS servers
      sp.TRACKER.verify(info.username, info.tracker, info.session, callback);
    } else {
      //POST request from the user's browser (from widgets)
      sp.TRACKER.verify(info.account, info.code, undefined, callback);
    }
  };

  sp.SSO = {};
  //handle GET request when user lands on SSO endpoint coming from SAASPASS SSO Login page
  sp.SSO.handleRequest = function(request, callback) {
    var account = request.query.account;
    var tracker = request.query.tracker;
    sp.TRACKER.verify(account, tracker, undefined, callback);
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
