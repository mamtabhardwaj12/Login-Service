/**
 * Created By :- Akshay
 * Created Date :- 09-11-2017 05:00 am
 * Version :- 1.0.0
 * Updated By :- Akshay
 * Updated Date :- 29-11-2017 10:00 pm
 * Version :- 1.1.0 
 */
// call the packages we need
var express = require('express');                       // call express
var app = express();                                    // define our app using express
var bodyParser = require('body-parser');                // configure app to use router()
var router = express.Router();                          // get an instance of the express Router
var userService = require('../app/api/svr.login');       // call userservice 
var config = require('./../config/config.json');           // call configration file
var port = process.env.PORT || config.port;             // set our port
var swaggerUi = require('swagger-ui-express');
var swaggerDocument = require('./../doc/swagger.json'); //Path of swagger.json file in your app directory
var morgan = require('morgan');
var winston = require('./../config/wintston');

// this will let us get the data from a POST
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

//Expose your swagger documentation through your express framework
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerDocument)); 


app.use(morgan('combined', { stream: winston.stream }));

// error handler for logging using winston
app.use(function(err, req, res, next) {
    // set locals, only providing error in development
    res.locals.message = err.message;
    res.locals.error = req.app.get('env') === 'development' ? err : {};
  
    // add this line to include winston logging
    winston.error(`${err.status || 500} - ${err.message} - ${req.originalUrl} - ${req.method} - ${req.ip}`);
  
    // render the error page
    res.status(err.status || 500);
    // next();
    res.send('error');
  });



router.post('/login', authenticateUser);          //authentication is done here (http://localhost:8082/api/)
router.get('/login', getUser);                   //authentication is done here (http://localhost:8082/api/)
router.put('/login', changePW);                   //authentication is done here (http://localhost:8082/api/)
router.post('/login/forgotPassword',forgotPW);  //authentication is done here (http://localhost:8082/login)
router.put('/login/forgotPassword',forgotUpdatePW);   //authentication is done here (http://localhost:8082/login)

module.exports = router;

function authenticateUser(req, res) {
    
    userService.authenticate(req,res)
        .then(function (token) {
            if (token) {
                res.send({ 
                    message : 'Login Successful.',         // authentication successful and send token
                    token : token
                });
            } else {                                       // authentication failed
                res.status(401).send({message : 'Username or password is incorrect'});
            }
        })
        .catch(function (err) {
            res.status(400).send(err);
        });
}

function getUser(req, res) {
    console.log("get ",req.query)
    userService.getUser(req,res)
        .then(function (data) {                                 
            res.send(data);
        })
        .catch(function (err) {
            res.status(400).send(err);
        });
}

function changePW(req, res) {
    userService.changePW(req,res)
        .then(function (data) {                                 
            res.send(data);
        })
        .catch(function (err) {
            res.status(400).send(err);
        });
}

function forgotPW(req, res) {
    userService.forgotPW(req,res)
        .then(function (data) {                                 
            res.send(data);
        })
        .catch(function (err) {
            res.status(400).send(err);
        });
}

function forgotUpdatePW(req, res) {
    userService.forgotUpdatePW(req,res)
        .then(function (data) {                                 
            res.send(data);
        })
        .catch(function (err) {
            res.status(400).send(err);
        });
}

router.get('/', function (req, res) {                       //for testing the api service (http://localhost:8082/)
    res.json({ message: 'hooray! welcome to our api!' });
});

//---------------------------REGISTER OUR ROUTES ---------------------------
app.use('', router);                                    // all of our routes will be prefixed with /api

// ================= START THE SERVER=======================================
var server = app.listen(port, function () {
    console.log('Server listening at http://localhost:' + server.address().port);
});

module.exports = server