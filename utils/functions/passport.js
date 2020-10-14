const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const bodyParser = require('body-parser');
const { verify } = require('hcaptcha');
const mongo = require('./mongo.js');
const { genPassword, validPassword } = require('./password.js');
const shared = require('../shared');

// hCaptcha SETUP
const hcaptchaSecret = process.env.HCAPTCHA_SECRET || '0x0000000000000000000000000000000000000000';

module.exports = (app, mongo) => {
    passport.use(new LocalStrategy({
            passReqToCallback: true
        }, (req, username, password, cb) => {
            verify(hcaptchaSecret, req.body['h-captcha-response']).then((data) => { if (data['success']) {
                return cb(null, shared.auth(username, password, false));
            } else {
                return cb(null, false);
            }}).catch(console.error);
        }
    ));
    passport.serializeUser(function (user, cb) {
        cb(null, user.id);
    });
    passport.deserializeUser(function (id, cb) {
        mongo.User.findById(id, function (err, user) {
            if (err) { return cb(err); }
            cb(null, user);
        });
    });

    app.use(bodyParser.urlencoded({ extended: true }));
    app.use(passport.initialize());
    app.use(passport.session());
}
