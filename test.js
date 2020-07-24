const requestHandlerSecure = require("./component.request.handler.secure.js");
const delegate = require("component.delegate");
const utils = require("utils");
const logging = require("logging");
logging.config.add("Request Handler Secure");
( async() => {

    delegate.register("blabla", "3000/test", ({ privateKey, hashedPassphrase }) => {
        logging.write("Request Handler Secure Authenticate",`PrivateKey: ${privateKey}`);
        logging.write("Request Handler Secure Authenticate",`HasedPassphrase: ${hashedPassphrase}`);
        let statusMessage = "Success";
        return { 
            headers: { "Content-Type":"text/plain" },
            statusCode: 200, 
            statusMessage,
            data: statusMessage
        };
    });

    //Secure
    const { hashedPassphrase, hashedPassphraseSalt } = utils.hashPassphrase("secure1");
    await requestHandlerSecure.handle("blabla",{
        privateHost: "localhost",
        privatePort: 3000,
        publicHost: "localhost",
        publicPort: 3000,
        path: "/test",
        hashedPassphrase,
        hashedPassphraseSalt
    });
    await requestHandlerSecure.handle("blabla",{
        privateHost: "localhost",
        privatePort: 4000,
        publicHost: "localhost",
        publicPort: 4000,
        path: "/test",
        hashedPassphrase,
        hashedPassphraseSalt
    });

    //Unsecure
    await requestHandlerSecure.handle("blabla",{
        privateHost: "localhost",
        privatePort: 5000,
        publicHost: "localhost",
        publicPort: 5000,
        path: "/test"
    });

})().catch((err)=>{
    console.error(err);
});