/*jslint node:true*/

/*global describe, it, before, after, beforeEach, afterEach*/

'use strict';

var Relay = require('../');
var torrequest = require('torrequest');

describe('Tor Relay', function () {
    describe('Instantiation', function () {
        it('should instantiate the Relay', function () {
            var relay = new Relay();

        });
        it('should instantiate the Relay with options', function () {
            var relay = new Relay({
                controlPassword: 'test',
                controlPort: 1234,
                socksUsername: 'test',
                socksPassword: 'test',
                socksPort: 1235,
                timeout: 54321,
                retries: 7
            });

            if (relay.service.control.password !== 'test') {
                throw new Error('Wrong control password');
            }
            if (relay.service.control.port !== 1234) {
                throw new Error('Wrong control port');
            }
            if (relay.service.socks.password !== 'test') {
                throw new Error('Wrong socks password');
            }
            if (relay.service.socks.port !== 1235) {
                throw new Error('Wrong socks port');
            }
            if (relay.service.socks.username !== 'test') {
                throw new Error('Wrong socks username');
            }
            if (relay.timeout !== 54321) {
                throw new Error('Wrong timeout');
            }
            if (relay.retries !== 7) {
                throw new Error('Wrong number of retries');
            }
        });
    });
    describe('Starting and stopping', function () {
        var relay;
        before(function () {
            relay = new Relay({
                timeout: 10000,
                retries: 3
            });
        });
        it('should start a relay and should use retries', function (done) {
            this.timeout(40000);
            relay.on('notice', function (event) {
                console.log('NOTICE: ' + event.message);
            });
            relay.on('warn', function (event) {
                console.log('WARN: ' + event.message);
            });
            relay.start(done);
        });

        it('should be able to get info by tor-control', function (done) {
            relay.control.getInfo('version', done);
        });
        it('should stop a relay', function (done) {
            relay.stop(done);

        });
        it('should start a relay again', function (done) {
            this.timeout(60000);
            relay.start(done);
        });
        it('should be able to get info by tor-control again', function (done) {
            relay.control.getInfo('version', done);
        });
    });

    describe('Access to socks', function () {
        var relay;
        before(function (done) {
            this.timeout(60000);
            relay = new Relay({
                socksUsername: false,
                socksPassword: false
            });
            relay.start(done);
        });
        it('should make an accessible socks port', function (done) {
            this.timeout(10000);
            torrequest({
                uri: 'https://github.com/atd-schubert/',
                torHost: 'localhost',
                torPort: relay.service.socks.port
            }, function (err) {
                if (err) {
                    return done(err);
                }
                return done();
            });
        });
    });
});