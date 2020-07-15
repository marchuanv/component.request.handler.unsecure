const utils = require("utils");
const crypto = require("crypto");
const requestHandler = require("component.request.handler.user");
const delegate = require("component.delegate");
const base64 = /^([A-Za-z0-9+/]{4})*([A-Za-z0-9+/]{4}|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{2}==)$/;

const logging = require("logging");
logging.config.add("Request Handler Secure");

const isBase64String = (str) => {
    base64.lastIndex = 0;
    return base64.test(str);
};

const stringToBase64 = (str) => {
    return Buffer.from(str, "utf8").toString("base64");
}

const base64ToString = (base64Str) => {
    return Buffer.from(base64Str, "base64").toString("utf8");;
}

const encryptToBase64Str = (dataStr, encryptionkey) => {
    const dataBuf = Buffer.from(dataStr, "utf8");
    return crypto.publicEncrypt( { 
        key: encryptionkey,
        padding: crypto.constants.RSA_PKCS1_PADDING
    }, dataBuf).toString("base64");
}

const decryptFromBase64Str = (base64Str, decryptionKey, passphrase) => {
    const dataBuf = Buffer.from(base64Str, "base64");
    return crypto.privateDecrypt({ 
        key: decryptionKey,
        passphrase,
        padding: crypto.constants.RSA_PKCS1_PADDING
    }, dataBuf).toString("utf8");
}

const generateKeys = (passphrase) => {
    return crypto.generateKeyPairSync('rsa', { modulusLength: 4096,
        publicKeyEncoding: { type: 'spki', format: 'pem'},
        privateKeyEncoding: { type: 'pkcs8', format: 'pem', cipher: 'aes-256-cbc', passphrase }
    });
};

function SecureSession({ username, fromhost, fromport, hashedPassphrase, hashedPassphraseSalt }) {
    
    this.id = utils.generateGUID();
    this.fromhost = fromhost;
    this.fromport = fromport;
    this.username = username;

    this.authorise = () => {
        const { publicKey, privateKey } = generateKeys(hashedPassphrase);
        this.privateKey = privateKey;
        this.publicKey = publicKey;
        this.encryptedPassphrase = encryptToBase64Str(hashedPassphrase, publicKey);
        this.token = encryptToBase64Str(utils.getJSONString({ username , fromhost, fromport }), publicKey);
    };

    this.authenticate = ({ passphrase }) => {
        if (passphrase){
            const results = utils.hashPassphrase(passphrase, hashedPassphraseSalt);
            if (results.hashedPassphrase === hashedPassphrase){
                return true;
            }
        } 
        if (hashedPassphrase === passphrase){
            return true;
        }
        return false;
    };

    this.getEncryptionKey = () => {
        return stringToBase64(this.publicKey);
    };

    this.encryptData= ({ encryptionkey, data } ) => {
        const encryptedData = encryptToBase64Str(data, base64ToString(encryptionkey || "") || this.publicKey );
        return encryptedData;
    };
    
    this.decryptData = ({ data } ) => {
        const decryptedData = decryptFromBase64Str(data, this.privateKey, hashedPassphrase);
        return decryptedData;
    };
}

module.exports = { 
    sessions: [],
    handle: (callingModule, options) => {
        const thisModule = `component.request.handler.secure.${options.path.replace(/\//g,"")}.${options.publicPort}`;
        const thisLoginModule = `component.request.handler.secure.login.${options.publicPort}`;
        delegate.register(thisModule, async ( { headers, data }) => {
            ({ username, token, fromhost, fromport } = headers);
            const requestUrl = `${options.publicHost}:${options.publicPort}${options.path}`;
            let session = module.exports.sessions.find(s => s.token === token);
            if (session) {
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

        delegate.register(thisLoginModule, async ({ headers: { username, passphrase, fromhost, fromport }  }) => {
            const index = module.exports.sessions.findIndex(s => s.username === username && s.fromhost === fromhost && s.fromport === fromport );
            let session = module.exports.sessions[index];
            if (session){
                const statusMessage = "Success";
                return { 
                    headers: { 
                        "Content-Type":"text/plain", 
                        "Content-Length": Buffer.byteLength(statusMessage),
                        token: session.token,
                        encryptionkey: session.getEncryptionKey()
                    },
                    statusCode: 200, 
                    statusMessage,
                    data: statusMessage
                };
            }
            if (index > -1){
                module.exports.sessions.splice(index,1);
            }
            const requestUrl = `${options.publicHost}:${options.publicPort}${options.path}`;
            if (username && fromhost && fromport ) { //secured
                let { hashedPassphrase, hashedPassphraseSalt } = options;
                if (!hashedPassphrase || !hashedPassphraseSalt){ // unsecured
                    logging.write("Request Handler Secure",`request handler is not passphrase proected`);
                    passphrase = "unsecured";
                    ({ hashedPassphrase, hashedPassphraseSalt } = utils.hashPassphrase(passphrase));
                }
                logging.write("Request Handler Secure",`creating new session for ${requestUrl}`);
                session = new SecureSession({ username, fromhost, fromport, hashedPassphrase, hashedPassphraseSalt });
                if ( ( passphrase || hashedPassphrase ) && session.authenticate({ passphrase: passphrase || options.hashedPassphrase }) === true ){
                    session.authorise();
                    module.exports.sessions.push(session);
                    const statusMessage = "Success";
                    return { 
                        headers: { 
                            "Content-Type":"text/plain", 
                            "Content-Length": Buffer.byteLength(statusMessage),
                            token: session.token,
                            encryptionkey: session.getEncryptionKey()
                        },
                        statusCode: 200, 
                        statusMessage,
                        data: statusMessage
                    };
                }
            } 
            logging.write("Request Handler Secure",`${requestUrl} is unauthorised.`);
            const statusMessage = "Unauthorised";
            return { 
                headers: { "Content-Type":"text/plain", "Content-Length": Buffer.byteLength(statusMessage) },
                statusCode: 401, 
                statusMessage,
                data: statusMessage
            };
        });

        requestHandler.handle(thisModule, { host: options.privateHost, port: options.privatePort, path: options.path });
        requestHandler.handle(thisLoginModule, { host: options.privateHost, port: options.privatePort, path: "/login" });
    }
};