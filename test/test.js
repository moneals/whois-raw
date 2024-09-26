/*
 * decaffeinate suggestions:
 * DS102: Remove unnecessary code created because of implicit returns
 * Full docs: https://github.com/decaffeinate/decaffeinate/blob/master/docs/suggestions.md
 */
const whois = require('..');

describe('#lookup()', function() {
    it('should work with google.com', done =>
        whois.lookup('google.com', function(err, data) {
            expect(err).toBeNull();
            data = data.toLowerCase();
            expect(data).toContain('domain name: google.com');
            return done();
        })
    );

    it('should work with 50.116.8.109', done =>
        whois.lookup('50.116.8.109', function(err, data) {
            expect(err).toBeNull();
            data = data.toLowerCase();
            expect(data).toContain('netname:        linode-us');
            return done();
        })
    );

    it('should work with 2001:0db8:11a3:09d7:1f34:8a2e:07a0:765d', done =>
        whois.lookup('2001:0db8:11a3:09d7:1f34:8a2e:07a0:765d', function(err, data) {
            expect(err).toBeNull();
            data = data.toLowerCase();
            expect(data).toContain('inet6num:       2001:db8::/32');
            return done();
        })
    );

    it('should honor specified WHOIS server', done =>
        whois.lookup('gandi.net', {server: 'whois.gandi.net'}, function(err, data) {
            expect(err).toBeNull();
            data = data.toLowerCase();
            expect(data).toContain('whois server: whois.gandi.net');
            expect(data).toContain('domain name: gandi.net');
            return done();
        })
    );

    it('should honor specified WHOIS server with port override', done =>
        whois.lookup('tucows.com', {server: 'whois.tucows.com:43'}, function(err, data) {
            expect(err).toBeNull();
            data = data.toLowerCase();
            expect(data).toContain('whois server: whois.tucows.com');
            expect(data).toContain('domain name: tucows.com');
            return done();
        })
    );

    it('should follow specified number of redirects for domain', done =>
        whois.lookup('google.com', {follow: 1}, function(err, data) {
            expect(err).toBeNull();
            data = data.toLowerCase();
            expect(data).toContain('domain name: google.com');
            return done();
        })
    );

    it('should follow specified number of redirects for IP address', done =>
        whois.lookup('176.58.115.202', {follow: 1}, function(err, data) {
            expect(err).toBeNull();
            data = data.toLowerCase();
            expect(data).toContain('inetnum:        176.58.112.0 - 176.58.119.255');
            return done();
        })
    );

    it('should work with nic.sh', done =>
        whois.lookup('nic.sh', function(err, data) {
            expect(err).toBeNull();
            data = data.toLowerCase();
            expect(data).toContain('registry domain id: d503300000040403495-lrms');
            return done();
        })
    );

    it('should work with nic.io', done =>
        whois.lookup('nic.io', function(err, data) {
            expect(err).toBeNull();
            data = data.toLowerCase();
            expect(data).toContain('registry domain id: d503300000040453277-lrms');
            return done();
        })
    );

    it('should work with nic.ac', done =>
        whois.lookup('nic.ac', function(err, data) {
            expect(err).toBeNull();
            data = data.toLowerCase();
            expect(data).toContain('registry domain id: d503300000040632620-lrms');
            return done();
        })
    );

    it('should work with nic.tm', done =>
        whois.lookup('nic.tm', function(err, data) {
            expect(err).toBeNull();
            data = data.toLowerCase();
            expect(data).toContain('status : permanent/reserved');
            return done();
        })
    );

    it('should work with nic.global', done =>
        whois.lookup('nic.global', function(err, data) {
            expect(err).toBeNull();
            data = data.toLowerCase();
            expect(data).toContain('registry domain id: d2836144-agrs');
            return done();
        })
    );

    it('should work with srs.net.nz', done =>
        whois.lookup('srs.net.nz', function(err, data) {
            expect(err).toBeNull();
            data = data.toLowerCase();
            expect(data).toContain('domain_name: srs.net.nz');
            return done();
        })
    );

    it('should work with redundant follow', done =>
        whois.lookup('google.com', {follow: 5}, function(err, data) {
            expect(err).toBeNull();
            data = data.toLowerCase();
            expect(data).toContain('domain name: google.com');
            return done();
        })
    );

    it('should work with küche.de', done =>
        whois.lookup('küche.de', function(err, data) {
            expect(err).toBeNull();
            data = data.toLowerCase();
            expect(data).toContain('domain: küche.de');
            expect(data).toContain('status: connect');
            return done();
        })
    );

    it('should work with google.co.jp in english', done =>
        whois.lookup('google.co.jp', function(err, data) {
            expect(err).toBeNull();
            data = data.toLowerCase();
            expect(data).toContain('a. [domain name]                google.co.jp');
            return done();
        })
    );

    it('should work with registry.pro', done =>
        whois.lookup('registry.pro', function(err, data) {
            expect(err).toBeNull();
            data = data.toLowerCase();
            expect(data).toContain('domain id: d107300000000006392-lrms');
            return done();
        })
    );

    it('should fail with google.com due to timeout', done =>
        whois.lookup('google.com', {timeout: 1}, function(err, data) {
            expect(err).not.toBeNull();
            expect(err.message).toEqual('lookup: timeout');
            return done();
        })
    );

    it('should succeed with google.com with timeout', done =>
        whois.lookup('google.com', {timeout: 10000}, function(err, data) {
            expect(err).toBeNull();
            data = data.toLowerCase();
            expect(data).toContain('domain name: google.com');
            return done();
        })
    );

    it('should work with åre.no', done =>
        whois.lookup('åre.no', function(err, data) {
            expect(err).toBeNull();
            data = data.toLowerCase();
            expect(data).toContain('åre.no');
            return done();
        })
    );

    it('should work with nic.digital', done =>
        whois.lookup('nic.digital', function(err, data) {
            expect(err).toBeNull();
            data = data.toLowerCase();
            expect(data).toContain('nic.digital');
            return done();
        })
    );

    it('should work with whois.nic.ai', done =>
        whois.lookup('whois.nic.ai', function(err, data) {
            expect(err).toBeNull();
            data = data.toLowerCase();
            expect(data).toContain('whois.nic.ai');
            return done();
        })
    );

    //TODO call something like https://api.getproxylist.com/proxy?lastTested=300&protocol[]=socks5 to test proxy
    // it('should work with proxy', done => {
    //     var whoisOptions = {
    //         proxy: {
    //             host: '118.190.206.86',
    //             port: 9999,
    //             // userId: "optional",
    //             // password: "optional",
    //             type: 5,
    //         },
    //         timeout: 30000,
    //     };
    //     whois.lookup('google.com', whoisOptions, function (err, data) {
    //         expect(err).toBeNull();
    //         assert.notEqual(data.toLowerCase().indexOf('domain name: google.com'), -1);
    //         return done();
    //     })
    // });

    it('should work with currentzoology.org', done =>
        whois.lookup('currentzoology.org', function(err, data) {
            expect(err).toBeNull();
            data = data.toLowerCase();
            expect(data).toContain('currentzoology.org');
            return done();
        })
    );

    it('should work with clz.do', done =>
        whois.lookup('clz.do', function(err, data) {
            expect(err).toBeNull();
            data = data.toLowerCase();
            expect(data).toContain('clz.do');
            return done();
        })
    );

    it('should work with orpheusmusic.com.ng', done =>
        whois.lookup('orpheusmusic.com.ng', function(err, data) {
            expect(err).toBeNull();
            data = data.toLowerCase();
            expect(data).toContain('orpheusmusic.com.ng');
            return done();
        })
    );

    it('should work with cityradio.co.bw', done =>
        whois.lookup('cityradio.co.bw', function(err, data) {
            expect(err).toBeNull();
            data = data.toLowerCase();
            expect(data).toContain('cityradio.co.bw');
            return done();
        })
    );
});
