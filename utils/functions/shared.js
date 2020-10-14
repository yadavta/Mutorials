// MODULE IMPORTS
const passport = require('passport');
const { verify } = require('hcaptcha');
var Filter = require('bad-words');

filter = new Filter();

// FUNCTION IMPORTS
const emailValidation = require('../utils/functions/emailValidation');
const { genPassword, validPassword } = require('../utils/functions/password');

module.exports = (app, mongo) => {
    auth = (username, password, api) => {
        username = username.toLowerCase();
        mongo.User.find({ username: username }).then((user) => {
            if (!user[0]) { return false; }

            const isValid = validPassword(password, user[0].hash, user[0].salt);

            if (isValid) {
                if (api) {
                    return true;
                } else {
                    return user[0];
                }
            } else {
                return false;
            }

        })
        .catch((err) => {
            return false;
        });
    });

    register: (email, username, password) => {
        var registerInputProblems1 = [];
        if (req.body.ign.length > 30){
            registerInputProblems1.push('Your username is too long.');
        }
        if (req.body.ign.length < 1) {
            registerInputProblems1.push('Please enter a username.');
        }
        if (!(/^[\w\-\.\~]+$/.test(req.body.ign))) {
            registerInputProblems1.push('Allowed username characters: letters, numbers, underscore, hyphen, period, and tilde.');
        }
        if (req.body.password.length < 7 || !(/\d/.test(req.body.password)) || !(/[a-zA-Z]/.test(req.body.password))) {
            registerInputProblems1.push('The password you entered does not meet the requirements.');
        }
        if (req.body.password!=req.body.confirmPassword) {
            registerInputProblems1.push('The passwords did not match. Please try again.');
        }
        if (!emailValidation.regexCheck(req.body.username)) {
            registerInputProblems1.push('The email you entered is not valid.');
        }
        if (!req.body.agreeTOS) {
            registerInputProblems1.push('You must agree to the Terms of Service and Privacy Policy to register an account with us.');
        }
        if (!req.body.agreeAge) {
            registerInputProblems1.push('You must be at least 13 years old, or have permission from your parent, guardian, teacher, or school to use Mutorials.');
        }
        if (!(/^\d+$/.test(req.body.age))) {
            registerInputProblems1.push('Please enter a valid age!');
        }
        if (req.body.ign != filter.clean(req.body.ign)) {
            registerInputProblems1.push("Username is not appropriate.");
        }
        if (registerInputProblems1.length) {
            return [false, registerInputProblems1];
        }
        const saltHash = genPassword(password);
        const salt = saltHash.salt;
        const hash = saltHash.hash;
        const newUser = new mongo.User({
            username: email,
            ign: username,
            hash: hash,
            salt: salt,
            profile: {
                name: '',
                location: 'Earth',
                age: req.body.age,
                bio: ''
            },
            // if emailConfirmCode == 0, then email is confirmed
            stats: {
                experience: 0,
                correct: 0,
                wrong: 0,
                collectedTags: []
            },
            rating: {
                physics: -1,
                chemistry: -1,
                biology: -1
            }
        });
        // check for duplicate user
        mongo.db.collection('users').findOne({ username: email }).then((user) => {
            if (user) {
                console.log('used');
                var registerInputProblems2 = [];
                if (user.ign == username) {
                    registerInputProblems2.push('This username is already taken.');
                } else { // has to be matching email
                    registerInputProblems2.push('This email is already in use.');
                }
                if (registerInputProblems2.length) {
                    return [false, registerInputProblems2];
                }
            } else {
                console.log('new one');
                newUser.save().then((user) => {
                    //passport.authenticate('local', {failureRedirect: '/signin', successRedirect: '/train'});
                    console.log(user);
                });
                var confirmCode;
                require('crypto').randomBytes(6, function (ex, buf) {
                    confirmCode = buf.toString('hex');
                    mongo.db.collection('users').findOneAndUpdate({ username: req.body.username }, { $set: { emailConfirmCode: confirmCode } });
                    emailValidation.emailCodeSend(req.body.username, confirmCode);
                    return [true];
                });
            }
        });

    });
}
