const requestHandlerSecureLogin = require("component.request.handler.secure.login");
const delegate = require("component.delegate");
const base64 = /^([A-Za-z0-9+/]{4})*([A-Za-z0-9+/]{4}|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{2}==)$/;
const logging = require("logging");
logging.config.add("Request Handler Secure");

const isBase64String = (str) => {
    base64.lastIndex = 0;
    return base64.test(str);
};

module.exports = { 
    sessions: [],
    handle: (callingModule, options) => {
        const thisModule = `component.request.handler.secure.${options.path.replace(/\//g,"")}.${options.publicPort}`;
        delegate.register(thisModule, async ( { headers, data, session }) => {
            ({ username, token, fromhost, fromport } = headers);
            const requestUrl = `${options.publicHost}:${options.publicPort}${options.path}`;
            if (session.token) {
                logging.write("Request Handler Secure",`using session ${session.id} for ${requestUrl}`);
                logging.write("Request Handler Secure",`decrypting data received from ${requestUrl}`);
                if (isBase64String(data)===true){
                    data = session.decryptData({ data }) || data;
                } else {
                    logging.write("Request Handler Secure",`decryption failed, data received from ${requestUrl} is not encrypted.`);
                }
                logging.write("Request Handler Secure",`encrypting data received from ${requestUrl} handler`);
                let results = await delegate.call(callingModule, { headers, data });
                if (results.error){
                    return results;
                }
                results.data = session.encryptData({ encryptionkey: headers.encryptionkey, data });
                results.headers.encryptionkey = session.getEncryptionKey();
                results.headers.token = session.token;
                results.fromhost = session.fromhost;
                results.fromport = session.fromport;
                results.headers["Content-Length"] = Buffer.byteLength(results.data);
                return results;
            } else if (!options.hashedPassphrase || !options.hashedPassphraseSalt) { 
                logging.write("Request Handler Secure",`request is not configured to be passphrase protected`);
                return await delegate.call(callingModule, { headers, data });
            } else {
                logging.write("Request Handler Secure",`${requestUrl} is unauthorised.`);
                const statusMessage = "Unauthorised";
                return {
                    headers: { "Content-Type":"text/plain", "Content-Length": Buffer.byteLength(statusMessage) },
                    statusCode: 401,
                    statusMessage,
                    data: statusMessage
                };
            }
        });
        requestHandlerSecureLogin.handle(thisModule, options);
    }
};