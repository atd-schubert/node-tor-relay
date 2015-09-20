# Tor Relay
Node.js module to create a [tor](https://www.torproject.org/) node or maybe also a relay.

*I have not found a better name for this module, all others were already taken by other modules, but they do not provide
the range of functionality I wanted to have).*

## How to install

```bash
# check pre-requirements!
npm install --save tor-relay
```

### Pre-requirements

You need to have a installed version of tor on your system. You can download it from
[torproject.org](https://www.torproject.org/docs/installguide.html.en). Or install it with your packet manager of your
choice:

- APT-GET (Debian, Ubuntu etc.): `sudo apt-get install tor`
- Port (MacOSX): `sudo port install tor`
- YUM (Feodory, CentOS): `sudo yum install tor` (maybe you have to add repos first)

*You should take a look at the [torproject-website](https://www.torproject.org/) in every case*

## How to use

```js
var TorRelay = require('tor-relay');

var relay = new TorRelay({

    controlPassword: 'test', // If not set, TorRelay will make a random password. Set to false or '' for no password.
    controlPort: 9051,       // If not set, TorRelay will find a random free port.
    socksPort: 9050          // If not set, TorRelay will find a random free port.
});

// Make this module verbose
relay.on('notice', function (event) {
    console.log(event.message); // Log tor notices for more information
});

relay.on('warn', function (event) {
    console.log(event.message); // Log tor warnings for more information
});

relay.start(function (err) {
    if (err) {
        return console.error(err);
    }
    // Tor is now connected into a circuit!
    // Your code here

    // get a new circuit
    relay.control.signalNewnym(function () {
        // now we have a new circuit in tor.
    });

    // Halt tor if you want to:
    relay.stop(function (err) {
        if (err) {
            return console.error(err);
        }
        // Tor is now stopped.
    });
});

```

## Methods

- `.start(callback)`: Start tor
- `.stop(callback)`: Stop tor
- `.restart(callback)`: Stop and start tor again (aka. restart).

## Properties

- `cleanUpOnExit`: Kill tor sub-process and temporary directory on exit? (default true)
- `dataDirectory`: Path to tor directory (default is a random temporary one).
- `process`: The spawned tor child process.
- `control`: Connected instance of [tor-control](https://github.com/atd-schubert/node-tor-control).
- `service`: Settings for services (not possible to change in running process, use restart method).
    - `socks`: Socks5 Tor service.
        - `username`: Username to access Socks service.
        - `password`: Password to access Socks service.
        - `port`: Port of Socks service.
    - `control`: Tor control service.
        - `password`: Password to access control service.
        - `port`: Port of control service.
