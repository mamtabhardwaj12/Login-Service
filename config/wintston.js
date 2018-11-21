/**
 * @author Girijashankar Mishra
 * @version 1.1.0
 * @since 17-Aug-2018
 */
var appRoot = require('app-root-path');
var winston = require('winston');
require('winston-daily-rotate-file');
var config = require('./config.json')
// define the custom settings for each transport (file, console)
var options = {
    file: {
        level: 'info',
        name: 'file.info',
        filename: `${appRoot}/logs/app.log`,
        handleExceptions: true,
        maxsize: config.logMaxSize, // 5MB
        zippedArchive: true,
        maxFiles: config.logMaxFile,
        format: winston.format.combine(
            winston.format.colorize({
                message: true
            }),
            winston.format.simple()
        ),
        timestamp: function () {
            var date = new Date();
            return date.getDate() + '/' + (date.getMonth() + 1) + ' ' + date.toTimeString().substr(0, 5) + ' [' + global.process.pid + ']';
        },
        prettyPrint: true,
    },
    errorFile: {
        level: 'error',
        name: 'file.error',
        filename: `${appRoot}/logs/error.log`,
        handleExceptions: true,
        maxsize: config.logMaxSize, // 5MB
        zippedArchive: true,
        maxFiles: config.logMaxFile,
        format: winston.format.combine(
            winston.format.colorize({
                message: true
            }),
            winston.format.simple()
        ),
        timestamp: function () {
            var date = new Date();
            return date.getDate() + '/' + (date.getMonth() + 1) + ' ' + date.toTimeString().substr(0, 5) + ' [' + global.process.pid + ']';
        },
        prettyPrint: true,
    },
    console: {
        level: 'debug',
        handleExceptions: true,
        format: winston.format.combine(
            winston.format.colorize({
                message: true
            }),
            winston.format.simple()
        ),
        timestamp: function () {
            var date = new Date();
            return date.getDate() + '/' + (date.getMonth() + 1) + ' ' + date.toTimeString().substr(0, 5) + ' [' + global.process.pid + ']';
        },
        prettyPrint: true,
    },
};


// instantiate a new Winston Logger with the settings defined above
var logger = winston.createLogger({
    transports: [
        new(winston.transports.DailyRotateFile)(options.file),
        new(winston.transports.DailyRotateFile)(options.errorFile),
        new winston.transports.Console(options.console)
    ],
    exitOnError: false, // do not exit on handled exceptions
});

// create a stream object with a 'write' function that will be used by `morgan`
logger.stream = {
    write: function (message, encoding) {
        // use the 'info' log level so the output will be picked up by both transports (file and console)
        logger.info(message);
    },
};

module.exports = logger;