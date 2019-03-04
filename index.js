/*
 * decaffeinate suggestions:
 * DS101: Remove unnecessary use of Array.from
 * DS102: Remove unnecessary code created because of implicit returns
 * DS205: Consider reworking code to avoid use of IIFEs
 * DS207: Consider shorter variations of null checks
 * DS208: Avoid top-level this
 * Full docs: https://github.com/decaffeinate/decaffeinate/blob/master/docs/suggestions.md
 */
const _ = require('underscore');
const net = require('net');
const socks = require('socks').SocksClient;
const punycode = require('punycode');
const util = require('util');


this.SERVERS = require('./servers.json');

this.lookup = (addr, options, done) => {
    let parts;
    if ((typeof done === 'undefined') && (typeof options === 'function')) {
        done = options;
        options = {};
    }

    _.defaults(options, {
            follow: 2,
            timeout: 60000
        }
    ); // 60 seconds in ms

    done = _.once(done);

    let { server } = options;
    let { proxy } = options;
    const { timeout } = options;

    if (!server) {
        switch (true) {
            case _.contains(addr, '@'):
                done(new Error('lookup: email addresses not supported'));
                return;
                break;

            case net.isIP(addr) !== 0:
                server = this.SERVERS['_']['ip'];
                break;

            default:
                var tld = punycode.toASCII(addr);
                while (true) {
                    server = this.SERVERS[tld];
                    if (!tld || server) {
                        break;
                    }
                    tld = tld.replace(/^.+?(\.|$)/, '');
                }
        }
    }

    if (!server) {
        done(new Error('lookup: no whois server is known for this kind of object'));
        return;
    }

    if (typeof server === 'string') {
        parts = server.split(':');
        server = {
            host: parts[0],
            port: parts[1]
        };
    }

    if (typeof proxy === 'string') {
        parts = proxy.split(':');
        proxy = {
            ipaddress: parts[0],
            port: parseInt(parts[1])
        };
    }

    _.defaults(server, {
            port: 43,
            query: "$addr\r\n"
        }
    );

    if (proxy) {
        _.defaults(proxy,
            {type: 5});
    }


    const _lookup = (socket, done) => {
        let idn = addr;
        if ((server.punycode !== false) && (options.punycode !== false)) {
            idn = punycode.toASCII(addr);
        }
        socket.write(server.query.replace('$addr', idn));

        let data = '';
        socket.on('data', chunk => {
            return data += chunk;
        });

        socket.on('timeout', () => {
            socket.destroy();
            return done(new Error('lookup: timeout'));
        });

        socket.on('error', err => {
            return done(err);
        });

        return socket.on('close', err => {
            if (options.follow > 0) {
                const match = data.replace(/\r/gm, '').match(/(ReferralServer|Registrar Whois|Whois Server|WHOIS Server|Registrar WHOIS Server):[^\S\n]*((?:r?whois|https?):\/\/)?(.*)/);
                if ((match != null) && (match[3] !== server.host)) {
                    options = _.extend({}, options, {
                            follow: options.follow - 1,
                            server: match[3].trim()
                        }
                    );
                    this.lookup(addr, options, (err, parts) => {
                        if (err != null) {
                            return done(err);
                        }

                        if (options.verbose) {
                            return done(null, [{
                                    server: server.trim(),
                                    data
                                }
                                ].concat(parts)
                            );
                        } else {
                            return done(null, parts);
                        }
                    });
                    return;
                }
            }

            if (options.verbose) {
                return done(null, [{
                    server: server.trim(),
                    data
                }
                ]);
            } else {
                return done(null, data);
            }
        });
    };

    if (proxy) {
        return socks.createConnection({
                proxy,
                destination: {
                    host: server.host,
                    port: server.port,
                    type: server.type
                },
                command: 'connect',
                timeout: timeout
            }
            , (err, info) => {
                if (err != null) {
                    return done(err);
                }
                if (timeout) {
                    info.socket.setTimeout(timeout);
                }

                _lookup(info.socket, done);

                return info.socket.resume();
            });

    } else {
        const sockOpts = {
            host: server.host,
            port: server.port
        };

        if (options.bind) {
            sockOpts.localAddress = options.bind;
        }

        const socket = net.connect(sockOpts);
        if (timeout) {
            socket.setTimeout(timeout);
        }
        return _lookup(socket, done);
    }
};


if (module === require.main) {
    const optimist = require('optimist')
        .usage('$0 [options] address')
        .default('s', null)
        .alias('s', 'server')
        .describe('s', 'whois server')
        .default('f', 0)
        .alias('f', 'follow')
        .describe('f', 'number of times to follow redirects')
        .default('p', null)
        .alias('p', 'proxy')
        .describe('p', 'SOCKS proxy')
        .boolean('v')
        .default('v', false)
        .alias('v', 'verbose')
        .describe('v', 'show verbose results')
        .default('b', null)
        .alias('b', 'bind')
        .describe('b', 'bind to a local IP address')
        .boolean('h')
        .default('h', false)
        .alias('h', 'help')
        .describe('h', 'display this help message');

    if (optimist.argv.h) {
        console.log(optimist.help());
        process.exit(0);
    }

    if ((optimist.argv._[0] == null)) {
        console.log(optimist.help());
        process.exit(1);
    }

    this.lookup(optimist.argv._[0], {server: optimist.argv.server, follow: optimist.argv.follow, proxy: optimist.argv.proxy, verbose: optimist.argv.verbose, bind: optimist.argv.bind}, (err, data) => {
        if (err != null) {
            console.log(err);
            process.exit(1);
        }

        if (util.isArray(data)) {
            return (() => {
                const result = [];
                for (let part of Array.from(data)) {
                    console.log(part.server.host);
                    console.log(part.data);
                    result.push(console.log);
                }
                return result;
            })();

        } else {
            return console.log(data);
        }
    });
}