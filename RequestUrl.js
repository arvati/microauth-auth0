const get_ip = require('ipware')().get_ip;

module.exports = (req, {trustProxy = true}) => {
    const getProtocol = (request) => {
        var proto = request.connection.encrypted ? 'https' : 'http';
        // only do this if you trust the proxy
        if (trustProxy) proto = request.headers['x-forwarded-proto'] || proto;
        return proto.split(/\s*,\s*/)[0];
    }
    const getHost = (request) =>{
        var host = request.headers['host']
        if (trustProxy) host = request.headers['x-forwarded-host'] || host;
        return host.split(/\s*,\s*/)[0]
    }
    const getIp = (request) => {
        const {clientIp, clientIpRoutable} = get_ip(req, false);
        const ip = (trustProxy) ? clientIp : null
        return {ip, clientIp, clientIpRoutable}
    }
    req['originalUrl'] = req.url
    const {origin, protocol, host, hostname, port, pathname, search, hash} = new URL(req.url, getProtocol(req) + '://' + getHost(req))
    req["origin"] = origin
    req["protocol"] = protocol
    req["host"] = host
    req["hostname"] = hostname
    req["port"] = port
    req["path"] = pathname
    req["hash"] = hash // Only here for documentation pourposes
    req["search"] = search // https://nodejs.org/api/url.html#url_class_urlsearchparams
    req["secure"] = ('https' == protocol)
    const {ip, clientIp, clientIpRoutable} = getIp(req)
    req["clientIp"] = clientIp
    req["clientIpRoutable"] = clientIpRoutable
    req["ip"] = ip
}