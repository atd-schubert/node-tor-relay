/*jslint node:true*/

'use strict';

var EventEmitter = require('events').EventEmitter;
var TorControl = require('tor-control');
var spawn = require('child_process').spawn;
var freeport = require('freeport');
var async = require('async');
var crypto = require('crypto');
var temp = require('temp');

/**
 * Create random credentials
 * @private
 * @returns {*}
 */
var createCredential = function () {
    return crypto.createHash('sha1')
        .update(Date.now().toString() + Math.random().toString())
        .digest('hex');
};

/**
 * Relay class for tor relays
 * @param {{}} [opts] - Options for relay
 * @param {boolean} [opts.autoCredentials] - Automatically create credentials
 * @param {boolean} [opts.cleanUpOnExit=true] - Remove temporary dir an close unused child-processes on exit
 * @param {string} [opts.dataDirectory] - Specify a directory to store tor data (default is an auto-created temporary dir, this will be removed if cleanUpOnExit is true)
 * @param {string} [opts.controlPassword] - Password for tor control (default is a random password)
 * @param {string} [opts.controlPort] - Port for tor control (default is a random free port)
 * @param {string} [opts.socksPort] - Port for socks5 (default is a random free port)
 * @param {string} [opts.socksUsername] - Username for socks5 (default is a random like a password)
 * @param {string} [opts.socksPassword] - Password for socks5 (default is a random password)
 * @constructor
 */
var Relay = function TorRelay(opts) {
    var self = this;
    opts = opts || {};

    if (!opts.hasOwnProperty('autoCredentials')) {
        opts.autoCredentials = true;
    }
    this.dataDirectory = opts.dataDirectory || null;

    if (!opts.hasOwnProperty('cleanUpOnExit')) {
        this.cleanUpOnExit = true;
    } else {
        this.cleanUpOnExit = opts.cleanUpOnExit;
    }

    /**
     * Configuration of the services
     * @type {{control: {password: (string|*), port: (string|*|null)}, socks: {port: (string|*|null)}}}
     */
    this.service = {
        control: {
            password:  opts.controlPassword || (opts.autoCredentials ? createCredential() : null),
            port: opts.controlPort || null
        },
        socks: {
            //username: opts.socksUsername || (opts.autoCredentials ? createCredential() : null),
            //password: opts.socksPassword || (opts.autoCredentials ? createCredential() : null),
            port: opts.socksPort || null
        }
    };

    if (!opts.hasOwnProperty('socksUsername') && opts.autoCredentials) {
        this.service.socks.username = createCredential();
    }
    if (!opts.hasOwnProperty('socksPassword') && opts.autoCredentials) {
        this.service.socks.password = createCredential();
    }


    process.on('exit', function () {
        if (self.process && self.cleanUpOnExit) {
            console.error('Killing tor sub-process');
            self.process.kill('SIGTERM');
            self.process.kill('SIGKILL');
        }
    });

};

Relay.prototype = {
    '__proto__': EventEmitter.prototype,

    control: null,

    // Methods
    /**
     * Start tor
     * @param {TorRelay~startCallback} cb - Start callback function
     * @returns {*}
     */
    start: function startRelay(cb) {
        var asyncArr = [],
            hashedPassword = '',
            self = this;

        if (this.process) {
            return cb();
        }

        if (!this.service.socks.port) {
            asyncArr.push(function (cb) {
                freeport(function (err, port) {
                    self.service.socks.port = port;
                    return cb(err);
                });
            });
        }
        if (!this.service.control.port) {
            asyncArr.push(function (cb) {
                freeport(function (err, port) {
                    self.service.control.port = port;
                    return cb(err);
                });
            });
        }

        if (!this.dataDirectory) {
            asyncArr.push(function (cb) {
                var dirname = crypto.createHash('sha1')
                    .update(Date.now().toString() + Math.random().toString())
                    .digest('hex');
                if (self.cleanUpOnExit) {
                    temp.track();
                }
                temp.mkdir(dirname, function (err, path) {
                    self.dataDirectory = path;
                    return cb(err);
                });
            });
        }

        // hash a password
        if (this.service.control.password) {
            asyncArr.push(function (cb) {
                var hashedPasswordCmd;

                hashedPasswordCmd = spawn('tor', ['--hash-password', self.service.control.password]);
                hashedPasswordCmd.stdout.on('data', function (data) {
                    hashedPassword += data.toString();
                });
                hashedPasswordCmd.stdout.on('end', function (status) {
                    if (status) {
                        return cb(new Error('Can not hash your password (Exit status: ' + status + ')'));
                    }
                    hashedPassword = hashedPassword.match(/16:[A-F0-9]{58}/)[0];
                    return cb();
                });
            });
        }

        async.parallel(asyncArr, function (err) {
            var listener = function (event) {
                    if (event.message.indexOf('Tor has successfully opened a circuit') !== -1) {
                        self.removeListener('notice', listener);
                        /**
                         * @event TorRequest#ready
                         */
                        self.emit('ready');
                        /**
                         * @callback TorRelay~startCallback
                         * @param {null| error} error - Error if there was one
                         */
                        return cb();
                    }
                },
                params = [//'--RunAsDaemon', '0',
                    '--CookieAuthentication', '0',
                    '--ControlPort', self.service.control.port,
                    //'--PidFile', 'tor.pid',
                    '--SocksPort', self.service.socks.port,
                    '--DataDirectory', self.dataDirectory];
            if (err) {
                return cb(err);
            }

            if (hashedPassword) {
                params.push('--HashedControlPassword', hashedPassword);
            }
            if (self.service.socks.username && self.service.socks.password) {
                params.push('--Socks5ProxyUsername', self.service.socks.username,
                    '--Socks5ProxyPassword', self.service.socks.password);
            }

            self.process = spawn('tor', params);
            self.process.on('exit', function () {
                self.process = null;
                self.control = null;
            });

            self.on('notice', listener);

            self.process.stdout.on('data', function (chunk) {
                var arr = chunk.toString().split(/\r?\n/),
                    i,
                    tmp,
                    year = (new Date()).getFullYear();

                for (i = 0; i < arr.length; i += 1) {
                    if (arr[i] !== '') {
                        tmp = {
                            type: arr[i].substring(arr[i].indexOf('[') + 1, arr[i].indexOf(']')),
                            date: new Date(arr[i].substr(0, 7) + year + arr[i].substr(6, 12)),
                            message: arr[i].substr(arr[i].indexOf(']') + 2),
                            data: arr[i]
                        };
                        /**
                         * @event TorRequest#notice
                         * @type {{}}
                         * @property {string} type - Type of message
                         * @property {Array} messages - Array of messages
                         * @property {number} code - Status code
                         * @property {string} type - Type of message
                         */
                        /**
                         * @event TorRequest#warn
                         * @type {{}}
                         * @property {string} type - Type of message
                         * @property {Array} messages - Array of messages
                         * @property {number} code - Status code
                         * @property {string} type - Type of message
                         */
                        self.emit(tmp.type, tmp);
                    }

                }


            });

            self.control = new TorControl({
                port: self.service.control.port,
                password: self.service.control.password
            });
        });

    },
    /**
     * Stop tor
     * @param {TorRelay~stopCallback} cb - Stop callback function
     * @returns {*}
     */
    stop: function stopRelay(cb) {
        var self = this;

        if (!this.control && !this.process) {
            return cb();
        }

        this.control.signalShutdown(function (err) {
            if (err) {
                return cb(err);
            }
            self.process.on('exit', function () {
                /**
                 * @callback TorRelay~stopCallback
                 * @param {null| error} error - Error if there was one
                 */
                return cb();
            });
        });
        return this;
    },

    /**
     * Stop and start relay
     * @param {TorRelay~startCallback} cb
     */
    restart: function restartRelay(cb) {
        var self = this;
        this.stop(function (err) {
            if (err) {
                return cb(err);
            }
            self.start(cb);
        });
    },

    // Properties
    /**
     * Remove temporary dir an close unused child-processes on exit
     * @type {boolean}
     */
    cleanUpOnExit: true,
    /**
     * Directory to store tor data
     * @type {string}
     */
    dataDirectory: null,
    /**
     * The tor child process
     * @type {process|null}
     */
    process: null,
    service: null

};

module.exports = Relay;
