const requestHandlerSecure = require("./component.request.handler.secure.js");
const delegate = require("component.delegate");
const utils = require("utils");
( async() => {

    const callingModule = "component.request.handler.secure";
    delegate.register(callingModule, () => {
        let statusMessage = "Success";
        return { 
            headers: { "Content-Type":"text/plain", "Content-Length": Buffer.byteLength(statusMessage) },
            statusCode: 200, 
            statusMessage,
            data: statusMessage
        };
    });

    //Secure
    let { hashedPassphrase, hashedPassphraseSalt } = utils.hashPassphrase("secure1");
    await requestHandlerSecure.handle(callingModule, {
        privateHost: "localhost",
        privatePort: 3000,
        publicHost: "localhost",
        publicPort: 3000,
        path: "/test",
        hashedPassphrase,
        hashedPassphraseSalt
    });
    ({ hashedPassphrase, hashedPassphraseSalt } = utils.hashPassphrase("secure2"));
    await requestHandlerSecure.handle(callingModule, {
        privateHost: "localhost",
        privatePort: 4000,
        publicHost: "localhost",
        publicPort: 4000,
        path: "/test",
        hashedPassphrase,
        hashedPassphraseSalt
    });

    //Unsecure
    await requestHandlerSecure.handle(callingModule, {
        privateHost: "localhost",
        privatePort: 5000,
        publicHost: "localhost",
        publicPort: 5000,
        path: "/test"
    });

})().catch((err)=>{
    console.error(err);
});