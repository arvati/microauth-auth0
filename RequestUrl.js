const {get_ip, is_private_ip, is_valid_ip, is_loopback_ip, cleanup_ip} = require('ipware')();
const proxyaddr = require('proxy-addr');
const originalurl=require('original-url');

module.exports = (req) => {
    const getIp = (request) => {
        //testing manually because do not want req to be populated with attibutes.
        var remoteIp = [
            "HTTP_X_FORWARDED_FOR",
            "HTTP_CLIENT_IP",
            "HTTP_X_REAL_IP",
            "HTTP_X_FORWARDED",
            "HTTP_X_CLUSTER_CLIENT_IP",
            "HTTP_FORWARDED_FOR",
            "HTTP_FORWARDED",
            "HTTP_VIA",
            "CF-Connecting-IP",
            "X-Real-IP",
            "X-Client-IP",
            "X-Forwarded-For",
            "REMOTE_ADDR"
          ].reduce(  // reduce getting acc as first headers name not null
                    (acc, key) => (req.headers[key] || 
                            req.headers[key.toUpperCase()] ||
                            req.headers[key.toLowerCase()] ||
                            req.headers[key.toLowerCase().replace(/_/g, '-')] ||
                            req.headers[key.toUpperCase().replace(/_/g, '-')] ||
                            request.connection.remoteAddress || '127.0.0.1').split(/\s*,\s*/).reduce(
                                (ret, cur) => {

                                }
                            )
                    ) || ;
        // todo: create another array.reduce inside above reduce to test each ip for cleanup_ip, is_valid_ip, is_private_ip, is_loopback_ip
        return remoteIp.split(/\s*,\s*/)[0]  //split this way gets first item from array separated by , with or without spaces
    }
    
    const getNow = (request) =>{
        return request.headers['x-now-deployment-url'] || '';
    }

    req['originalUrl'] = req.url
    const {origin, protocol, host, hostname, port, pathname, search, hash} = new URL(originalurl(req).full)
    req["origin"] = origin
    req["protocol"] = protocol
    req["host"] = host
    req["hostname"] = hostname
    req["port"] = port
    req["path"] = pathname
    req["hash"] = hash // Only here for documentation pourposes
    req["search"] = search // https://nodejs.org/api/url.html#url_class_urlsearchparams
    req["secure"] = ('https' == protocol)
    req["ip"] = getIp(req)
    const {clientIp, clientIpRoutable} = get_ip(req, false);
    req["clientIp"] = clientIp
    req["clientIpRoutable"] = clientIpRoutable
    req["nowUrl"] = getNow(req)
}