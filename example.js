var SaasPass = require("./index.js");

//configure API secrets
var app = {
  key: "your_application_api_key_here",
  password: "your_application_api_password"
};

var sp = SaasPass({key: app.key});

sp.authenticate(app.password, function(err, token) {
  if(err) return console.log(err);

  console.log("authentication success. token:", token);

  console.log("checking OTP:", process.argv[2]);

  sp.checkOtp(process.argv[2], process.argv[3], function(err){
    if(err) return console.log(err);
    console.log("OTP accepted.");
  });
});
