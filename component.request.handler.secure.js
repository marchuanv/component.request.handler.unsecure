const utils = require("utils");
const logging = require("logging");
const crypto = require("crypto");
const base64 = /^([A-Za-z0-9+/]{4})*([A-Za-z0-9+/]{4}|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{2}==)$/;

const isBase64String = (str) => {
    base64.lastIndex = 0;
    return base64.test(str);
};

const genRandomString = (length) => {
    return crypto.randomBytes(Math.ceil(length/2))
            .toString('hex') /** convert to hexadecimal format */
            .slice(0,length);   /** return required number of characters */
};

const sha512 = (password, salt) => {
    var hash = crypto.createHmac('sha512', salt); /** Hashing algorithm sha512 */
    hash.update(password);
    var value = hash.digest('hex');
    return { salt, hashedPassphrase: value };
};

const hashPassphrase = (userpassword, salt) => {
    salt = salt || genRandomString(16); /** Gives us salt of length 16 */
    return sha512(userpassword, salt);
}

const isExpiredSession = (expireDate) => {
    const currentDate = new Date();
    const expired = currentDate.getTime() > expireDate.getTime();
    return expired
}

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

function SecureSession({ username, hashedPassphrase, hashedPassphraseSalt, token, fromhost, fromport }) {
    
    this.id = utils.generateGUID();
    const { publicKey, privateKey } = generateKeys(hashedPassphrase);
    this.privateKey = privateKey;
    this.publicKey = publicKey;
    this.encryptedPassphrase = encryptToBase64Str(hashedPassphrase,  this.publicKey);
    this.token = token || encryptToBase64Str(utils.getJSONString({ username , fromhost, fromport }), this.publicKey);
    this.fromhost =fromhost;
    this.fromport =fromport;

    this.authenticate = ({ passphrase }) => {
        const results = hashPassphrase(passphrase, hashedPassphraseSalt);
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
    session: [],
    callback: async ({ publicHost, publicPort, path, requestHeaders, requestData }) => {
        const { username, passphrase, token, fromhost, fromport } = requestHeaders;
        const results = { headers: {}, statusCode: 200, statusMessage: "Success" };
        const requestUrl = `${publicHost}:${publicPort}${path}`;
        const handler = module.exports.http.handlers.find(h =>  h.publicHost === publicHost && h.publicPort === publicPort && h.path === path && h.security);
        if (handler){
            const isSecure = (handler.security.username !== undefined && handler.security.hashedPassphrase !== undefined && handler.security.hashedPassphraseSalt !== undefined);
            let session = module.exports.sessions.find(session => session.token === token);
            let decryptedData = "";
            if (session) {
                logging.write("Component Secure Server",`using session ${session.id} for ${requestUrl}`);
                logging.write("Component Secure Server",`decrypting data received from ${requestUrl}`);
                if (isBase64String(requestData)===true){
                    decryptedData = session.decryptData({ data: requestData }) || requestData;
                } else {
                    logging.write("Component Secure Server",`decryption failed, data received from ${requestUrl} is not encrypted.`);
                }
            } else if (username && passphrase && fromhost && fromport && isSecure === true) {
                if (handler.security.username === username){
                    const newSession = new SecureSession({ 
                        username, 
                        hashedPassphrase: handler.security.hashedPassphrase, 
                        hashedPassphraseSalt: handler.security.hashedPassphraseSalt, 
                        fromhost, 
                        fromport: Number(fromport),
                        token
                    });
                    if (newSession.authenticate({ passphrase })===true){
                        module.exports.sessions.push(newSession);
                        session = newSession;
                        logging.write("Component Secure Server",`new session ${session.id} created for ${requestUrl}`);
                    } else {
                        logging.write("Component Secure Server",`${requestUrl} is not authorised.`);
                    }
                }
                decryptedData = requestData;
            }
            if (isSecure === true && !session){
                const message = "Unauthorised";
                results.statusCode = 401;
                results.statusMessage = message;
                results.headers = { "Content-Type":"text/plain", "Content-Length": Buffer.byteLength(message) };
                results.data = message;
                return results;
            }
            if (isSecure === false){
                decryptedData = requestData;
            }
            const isPreflight = requestHeaders["access-control-request-headers"] !== undefined;
            if(isPreflight){
                results.headers["Content-Type"] = "text/plain";
                results.data = "";
            } else if (session) {
                const { data, contentType, statusCode } = await handler.callback({ fromhost: session.fromhost, fromport: session.fromport, data: decryptedData });
                logging.write("Component Secure Server",`encrypting data received from ${requestUrl} handler`);
                results.data = session.encryptData({ encryptionkey: requestHeaders.encryptionkey, data });
                results.headers["Content-Type"] = contentType;
                results.statusCode = statusCode || results.statusCode;
                results.headers.encryptionkey = session.getEncryptionKey();
                results.headers.token = session.token;
                results.fromhost = session.fromhost;
                results.fromport = session.fromport;
            } else {
                const { data, contentType, statusCode } = await handler.callback({ fromhost, fromport: Number(fromport), data: decryptedData });
                results.statusCode = statusCode || results.statusCode;
                results.headers["Content-Type"] = contentType;
                results.data = data;
            }
            results.headers["Content-Length"] = Buffer.byteLength(results.data);
            results.headers["Access-Control-Allow-Origin"] = "*";
            results.headers["Access-Control-Expose-Headers"] = "*";
            results.headers["Access-Control-Allow-Headers"] = "*";
            results.isSecure = isSecure;
        } else {
            const message = "Not Found";
            results.statusCode = 404;
            results.statusMessage = message;
            results.headers = { "Content-Type":"text/plain", "Content-Length": Buffer.byteLength(message) };
            results.data = message;
        }
        return results;
    }
};