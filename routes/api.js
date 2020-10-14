// MODULE IMPORTS
const bodyParser = require('body-parser');
var Filter = require('bad-words');

const shared = require('../utils/functions/shared');

filter = new Filter();

function appValidate(app_code) = { if ( process.env.APP_CODES.split(',').includes(app_code); ) }

module.exports = (app, mongo) => {
    app.post('/api/signup', (req, res, next) => {
        if (appValidate(req.body.app_code)) {
            result = shared.register(req.body.email, req.body.username, req.body.password);
            if (result[0]) {
                return res.json({
                    success: true
                });
            } else {
                return res.json({
                    success: false,
                    error: result[1]
                });
            }
        } else {
            return res.json({
                success: false,
                error: "Error 403: Forbidden. Incorrect app API code."
            });
        }
    }),

    app.post('/api/auth', (req, res, next) => {
        if (appValidate(req.body.app_code)) {
            if (shared.auth(req.body.email, req.body.password, true)) {
                mongo.db.collection('users').findOne({ username: req.body.email }).then((user) => {
                    return res.json({
                        success: true,
                        user_code: user._id
                    });
                }
            } else {
                return res.json({
                    success: false,
                    error: "Incorrect email or password."
                });
            });
        } else {
            return res.json({
                success: false,
                error: "Error 403: Forbidden. Incorrect app API code."
            });
        }
    })
}
