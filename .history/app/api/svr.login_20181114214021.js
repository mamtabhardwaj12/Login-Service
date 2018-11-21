/**
 * Created By :- Akshay
 * Created Date :- 29-11-2017 01:00 pm
 * Version :- 1.0.0
 */
var config = require('../../config/config.json');                       // call configration file
var _ = require('lodash');                                              // Load the full build. for manipulating objects and collections
var jwt = require('jsonwebtoken');                                      // for creating token
var bcrypt = require('bcryptjs');                                       // for hashing
var Q = require('q');                                                   // for promise 
var TinyURL = require('tinyurl')
var mongo = require('mongoskin');                                       // call mongodb    
var db = mongo.db(config.connectionString, { native_parser: true });    // mongodb connectivity
// db.bind('SCF');                                                       // bind the collection

var service = {};

service.authenticate = authenticate;
service.getUser = getUser;
service.changePW = changePW;
service.forgotPW = forgotPW;
service.forgotUpdatePW = forgotUpdatePW;

module.exports = service;
console.log("user==>>>");
function authenticate(req, res) {
    console.log("inside auth service==>>>",req.query);
    var deferred = Q.defer();

    if (!req.body.username) { deferred.reject({ error: "please enter username" }) }
    if (!req.body.password) { deferred.reject({ error: "please enter password" }) }
    if (!req.body.appName) { deferred.reject({ error: "please enter application name" }) }

    var username = req.body.username;
    var password = req.body.password;
    // console.log("password", password);
    var collectionName = req.body.appName;                              // create the collection based on appName
    db.bind(collectionName);                                            // bind the collection based on appName
    
    db.collection(collectionName).findOne({ username: username }, function (err, user) {
        if (err) deferred.reject(err.name + ': ' + err.message);
        console.log("user==<>", user);
        if (user && bcrypt.compareSync(password, user.hash)) {
            deferred.resolve(jwt.sign({ sub: user._id}, config.secret));    // authentication successful
        } else {
            deferred.resolve();                                              // authentication failed
        }
    });
    return deferred.promise;
}


function getUser(req, res) {
    var deferred = Q.defer();
    if (!req.query.username) { deferred.reject({ error: "please enter username" }) }
    if (!req.query.appName) { deferred.reject({ error: "please enter application name" }) }

    var username = req.query.username;
    var collectionName = req.query.appName;                              // create the collection based on appName
    db.bind(collectionName);                                            // bind the collection based on appName
    db.collection(collectionName).findOne({ username: username }, function (err, user) {
        if (err) deferred.reject(err.name + ': ' + err.message);

        deferred.resolve(user);
    });
    return deferred.promise;
}

/**
 * @author Akshay Misal
 * @param { } req
 * @param { } res
 * @description change password
 */
function changePW(req, res) {
    var deferred = Q.defer();

    if (!req.body.username) { deferred.reject({ error: "please enter username" }) }
    if (!req.body.appName) { deferred.reject({ error: "please enter application name" }) }
    if (!req.body.oldPassword) { deferred.reject({ error: "please enter oldPassword" }) }
    if (!req.body.newPassword) { deferred.reject({ error: "please enter newPassword" }) }
    if (!req.body.confirmPassword) { deferred.reject({ error: "please enter confirmPassword" }) }

    if (req.body.confirmPassword !== req.body.newPassword) {
        deferred.reject({ error: "oldPassword & confirmPassword does not match." })
    } else {
        var username = req.body.username;
        var collectionName = req.body.appName;                              // create the collection based on appName
        var oldPassword = req.body.oldPassword;

        db.bind(collectionName);                                            // bind the collection based on appName

        db.collection(collectionName).findOne({ username: username }, function (err, user) {

            if (err) deferred.reject(err.name + ': ' + err.message);

            if (user && bcrypt.compareSync(oldPassword, user.hash)) {
                deferred.resolve(updatePW(req, res));
            } else {
                deferred.reject({ error: "old password is wrong." })
            }

        });
    }
    return deferred.promise;
}


function updatePW(req, res) {
    var deferred = Q.defer();

    var username = req.body.username;
    var collectionName = req.body.appName;                              // create the collection based on appName
    var confirmPassword = req.body.confirmPassword;

    var hash = bcrypt.hashSync(confirmPassword, 10);             // add hashed password to user object with salt
    var set = {
        hash: hash
    };

    db.bind(collectionName);                                            // bind the collection based on appName

    db.collection(collectionName).update({ username: username }, { $set: set },
        function (err, doc) {
            if (err) deferred.reject(err.name + ': ' + err.message);
            deferred.resolve({ message: "Successfully change the password." });
        })
    return deferred.promise;
}

/**
 * @author Akshay Misal
 * @description This function will first check email. This function will create the Tiny-Url.
 */
function forgotPW(req, res) {
    var deferred = Q.defer();

    if (!req.body.email) { deferred.reject({ error: "please enter email" }) }
    if (!req.body.appName) { deferred.reject({ error: "please enter application name" }) }
    if (!req.body.url) { deferred.reject({ error: "please enter application URL" }) }

    var email = req.body.email;
    var collectionName = req.body.appName;                              // create the collection based on appName    

    db.bind(collectionName);

    db.collection(collectionName).findOne({ email: email }, function (err, user) {

        if (err) deferred.reject(err.name + ': ' + err.message);

        if (user) {
            var url = req.body.url;
            TinyURL.shorten(url, function (res, err) {
                deferred.resolve({ message: "Success", url: res })
            });
        } else {
            deferred.reject({ error: "email not found." })
        }

    });

    return deferred.promise;
}

/**
 * @author Akshay Misal
 * @description This function will change the password based on tinyURL.
 */
function forgotUpdatePW(req, res) {
    var deferred = Q.defer();

    if (!req.body.appName) { deferred.reject({ error: "please enter application name" }) }
    if (!req.body.username) { deferred.reject({ error: "please enter username" }) }
    if (!req.body.confirmPassword) { deferred.reject({ error: "please enter application confirm password" }) }
    if (!req.body.newPassword) { deferred.reject({ error: "please enter application new password" }) }

    var username = req.body.username;
    var confirmPassword = req.body.confirmPassword;
    var collectionName = req.body.appName;

    var hash = bcrypt.hashSync(confirmPassword, 10);             // add hashed password to user object with salt
    var set = {
        hash: hash
    };

    db.bind(collectionName);                                            // bind the collection based on appName

    db.collection(collectionName).update({ username: username }, { $set: set },
        function (err, doc) {
            if (err) deferred.reject(err.name + ': ' + err.message);
            deferred.resolve({ message: "Successfully change the password." });
        })

    return deferred.promise;
}