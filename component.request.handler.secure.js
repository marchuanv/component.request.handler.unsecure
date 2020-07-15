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

function SecureSession({ username, token, fromhost, fromport, hashedPassphrase, hashedPassphraseSalt }) {
    
    this.id = utils.generateGUID();
    this.fromhost = fromhost;
    this.fromport = fromport;
    this.username = username;

    this.authenticate = ({ passphrase }) => {
        const { publicKey, privateKey } = generateKeys(hashedPassphrase);
        this.privateKey = privateKey;
        this.publicKey = publicKey;
        this.encryptedPassphrase = encryptToBase64Str(hashedPassphrase, publicKey);
        this.token = token || encryptToBase64Str(utils.getJSONString({ username , fromhost, fromport }), publicKey);
        const results = utils.hashPassphrase(passphrase, hashedPassphraseSalt);
        return results.hashedPassphrase === hashedPassphrase;
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
        const thisModule = `component.request.handler.secure.${options.path.replace(/\//g,"")}.${options.privatePort}`;
        delegate.register(thisModule, async (request) => {
            let { username, passphrase, token, fromhost, fromport } = request.headers;
            let results = { headers: {}, statusCode: -1, statusMessage: "" };
            const requestUrl = `${options.publicHost}:${options.publicPort}${options.path}`;
            let session = module.exports.sessions.find(session => session.token === token);
            let decryptedData = "";
            if (session) {
                logging.write("Request Handler Secure",`using session ${session.id} for ${requestUrl}`);
                logging.write("Request Handler Secure",`decrypting data received from ${requestUrl}`);
                if (isBase64String(request.data)===true){
                    decryptedData = session.decryptData({ data: request.data }) || request.data;
                } else {
                    logging.write("Request Handler Secure",`decryption failed, data received from ${requestUrl} is not encrypted.`);
                }
            } else if (username && fromhost && fromport ) { //secured
                let { hashedPassphrase, hashedPassphraseSalt } = options;
                if (!hashedPassphrase || !hashedPassphraseSalt){ // unsecured
                    logging.write("Request Handler Secure",`request handler is not passphrase proected`);
                    passphrase = "unsecured";
                    ({ hashedPassphrase, hashedPassphraseSalt } = utils.hashPassphrase(passphrase));
                }
                session = module.exports.sessions.find(session => session.username === username);
                if (!session){
                    session = new SecureSession({ username, fromhost, fromport, token, hashedPassphrase, hashedPassphraseSalt});
                }
                if ( passphrase && session.authenticate({ passphrase }) === true ){
                    if (!module.exports.sessions.find(session => session.username === username)){
                        module.exports.sessions.push(session);
                        logging.write("Request Handler Secure",`new session ${session.id} created for ${requestUrl}`);
                    }
                } else {
                    module.exports.sessions = module.exports.sessions.filter(session => session.username !== username)
                    logging.write("Request Handler Secure",`${requestUrl} is unauthorised.`);
                    const message = "Unauthorised";
                    results.statusCode = 401;
                    results.statusMessage = message;
                    results.headers = { "Content-Type":"text/plain", "Content-Length": Buffer.byteLength(message) };
                    results.data = message;
                    return results;
                }
                decryptedData = request.data;
            } else {
                logging.write("Request Handler Secure",`${requestUrl} is unauthorised.`);
                const message = "Unauthorised";
                results.statusCode = 401;
                results.statusMessage = message;
                results.headers = { "Content-Type":"text/plain", "Content-Length": Buffer.byteLength(message) };
                results.data = message;
                return results;
            }
            logging.write("Request Handler Secure",`encrypting data received from ${requestUrl} handler`);
            results = await delegate.call(callingModule, { username, fromhost, fromport, data: decryptedData } );
            if (results.error){
                return results;    
            }
            results.data = session.encryptData({ encryptionkey: request.headers.encryptionkey, data: results.data });
            results.headers.encryptionkey = session.getEncryptionKey();
            results.headers.token = session.token;
            results.fromhost = session.fromhost;
            results.fromport = session.fromport;
            results.headers["Content-Length"] = Buffer.byteLength(results.data);
            return results;
        });
        requestHandler.handle(thisModule, { port: options.privatePort, path: options.path });
    }
};