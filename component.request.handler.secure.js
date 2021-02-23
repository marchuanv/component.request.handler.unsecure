const requestHandlerSecureAuthenticate = require("component.request.handler.secure.authenticate");
const utils = require("utils");
const delegate = require("component.delegate");
const logging = require("logging");
logging.config.add("Request Handler Secure");

module.exports = { 
    handle: (context, options) => {
        const name = `${options.port}${options.path}`;
        const isPassphraseProtected = (
            ( options.hashedPassphrase !== null && options.hashedPassphrase !== "" && options.hashedPassphrase !== undefined) &&
            ( options.hashedPassphraseSalt !== null && options.hashedPassphraseSalt !== "" && options.hashedPassphraseSalt !== undefined)
        );
        delegate.register("component.request.handler.secure", name, async ( { session, headers, data }) => {
            if (!isPassphraseProtected) { 
                logging.write("Request Handler Secure",`${options.host}:${options.port}${options.path} is not passphrase protected`);
                return await delegate.call({ context, name }, { data });
            }
            const requestUrl = `${options.host}:${options.port}${options.path}`;;
            if (session){
                logging.write("Request Handler Secure",`decrypting data received from ${requestUrl}`);
                const decryptedData = utils.decryptFromBase64Str(data, session.privateKey, session.hashedPassphrase);
                if (!decryptedData) {
                    return {
                        headers: { "Content-Type":"text/plain" },
                        statusCode: 400,
                        statusMessage:"400 Bad Request",
                        data: "400 Bad Request failed to decrypt data"
                    };
                }
                logging.write("Request Handler Secure",`encrypting data received from ${requestUrl} handler`);
                let results = await delegate.call({ context, name }, { data: decryptedData });
                if (results.message && results.stack){
                    return results;
                } 
                if (results) {
                    if (results.data){
                        const encryptedData = utils.encryptToBase64Str(results.data, utils.base64ToString(session.encryptionkey.remote));
                        if (encryptedData){
                            results.data = encryptedData;
                        } else {
                            return {
                                headers: { "Content-Type":"text/plain" },
                                statusCode: 400,
                                statusMessage:"400 Bad Request",
                                data: "400 Bad Request failed to encrypt data"
                            };
                        }
                    }
                }
                return results;
            }
            logging.write("Request Handler Secure",`${requestUrl} is unauthorised.`);
            const statusMessage = "Unauthorised";
            return {
                headers: { "Content-Type":"text/plain" },
                statusCode: 401,
                statusMessage,
                data: statusMessage
            };
        });
        requestHandlerSecureAuthenticate.handle(options);
    }
};