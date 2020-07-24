const requestHandlerSecureAuthenticate = require("component.request.handler.secure.authenticate");
const crypto = require("crypto");
const delegate = require("component.delegate");
const base64 = /^([A-Za-z0-9+/]{4})*([A-Za-z0-9+/]{4}|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{2}==)$/;
const logging = require("logging");
logging.config.add("Request Handler Secure");

const isBase64String = (str) => {
    base64.lastIndex = 0;
    return base64.test(str);
};

const base64ToString = (base64Str) => {
    return Buffer.from(base64Str, "base64").toString("utf8");;
}

const decryptFromBase64Str = (base64Str, decryptionKey, passphrase) => {
    const dataBuf = Buffer.from(base64Str, "base64");
    return crypto.privateDecrypt({ 
        key: decryptionKey,
        passphrase,
        padding: crypto.constants.RSA_PKCS1_PADDING
    }, dataBuf).toString("utf8");
};

const encryptToBase64Str = (dataStr, encryptionkey) => {
    const dataBuf = Buffer.from(dataStr, "utf8");
    return crypto.publicEncrypt( { 
        key: encryptionkey,
        padding: crypto.constants.RSA_PKCS1_PADDING
    }, dataBuf).toString("base64");
};

module.exports = { 
    sessions: [],
    handle: (context, options) => {
        const name = `${options.publicPort}${options.path}`;
        delegate.register("component.request.handler.secure", name, async ( { headers, data, privateKey, hashedPassphrase, publicPort }) => {
            if (!options.hashedPassphrase || !options.hashedPassphraseSalt) { 
                logging.write("Request Handler Secure",`${options.publicHost}:${options.publicPort}${options.path} is not passphrase protected`);
                return await delegate.call({ context, name }, { headers, data });
            }
            const requestUrl = `${options.publicHost}:${options.publicPort}${options.path}`;
            let session = module.exports.sessions.find( s => s.token === headers.token && s.publicPort === publicPort);
            if (session){
                logging.write("Request Handler Secure",`decrypting data received from ${requestUrl}`);
                if (isBase64String(data)===true){
                    data = decryptFromBase64Str(data, session.privateKey, hashedPassphrase);
                } else {
                    logging.write("Request Handler Secure",`decryption failed, data received from ${requestUrl} is not encrypted.`);
                }
                
                logging.write("Request Handler Secure",`encrypting data received from ${requestUrl} handler`);
                let results = await delegate.call({ context, name }, { headers, data });
                if (results){
                    if (results.data){
                        results.data = encryptToBase64Str(data, base64ToString(headers.encryptionkey));
                    }
                    results.headers.encryptionkey = session.encryptionkey
                    results.fromhost = headers.fromhost;
                    results.fromport = headers.fromport;
                }
                return results;
            } else if (privateKey && headers.token && headers.encryptionkey) {
                module.exports.sessions.push({ 
                    token: headers.token,
                    encryptionkey: headers.encryptionkey,
                    privateKey,
                    publicPort
                });
                logging.write("Request Handler Secure",`${requestUrl} is authorised.`);
                const statusMessage = "Authorised";
                return {
                    headers,
                    statusCode: 200,
                    statusMessage,
                    data: statusMessage
                };
            } else {
                logging.write("Request Handler Secure",`${requestUrl} is unauthorised.`);
                const statusMessage = "Unauthorised";
                return {
                    headers: { "Content-Type":"text/plain" },
                    statusCode: 401,
                    statusMessage,
                    data: statusMessage
                };
            }
        });
        requestHandlerSecureAuthenticate.handle(options);
    }
};