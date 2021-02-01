const requestHandlerSecure = require("./component.request.handler.secure.js");
const delegate = require("component.delegate");
const request = require("component.request");
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

    //Secure With Correct Password
    let { hashedPassphrase, hashedPassphraseSalt } = utils.hashPassphrase("secure1");
    await requestHandlerSecure.handle("blabla",{
        host: "localhost",
        port: 3000,
        path: "/test",
        hashedPassphrase,
        hashedPassphraseSalt
    });
    let results = await request.send({ 
        host: "localhost",
        port: 3000,
        path: "/authenticate",
        method: "GET",
        headers: { 
            username: "marchuanv",
            fromhost: "localhost",
            fromport: 6000,
            passphrase: "secure1"
        }, 
        data: "",
        retryCount: 1
    });
    if (results.statusCode !== 200){
        throw "Secure With Correct Password Test Failed";
    }

    //Secure With Incorrect Password Same Port
    ({ hashedPassphrase, hashedPassphraseSalt } = utils.hashPassphrase("secure2"));
    await requestHandlerSecure.handle("blabla",{
        host: "localhost",
        port: 3000,
        path: "/test",
        hashedPassphrase,
        hashedPassphraseSalt
    });
    results = await request.send({ 
        host: "localhost",
        port: 3000,
        path: "/authenticate",
        method: "GET",
        headers: { 
            username: "marchuanv",
            fromhost: "localhost",
            fromport: 6000,
            passphrase: "secure1"
        }, 
        data: "",
        retryCount: 1
    });
    if (results.statusCode !== 401){
        throw "Secure With Incorrect Password Same Port Test Failed";
    }

    //Secure With Incorrect Password Different Port
    ({ hashedPassphrase, hashedPassphraseSalt } = utils.hashPassphrase("secure2"));
    await requestHandlerSecure.handle("blabla",{
        host: "localhost",
        port: 4000,
        path: "/test",
        hashedPassphrase,
        hashedPassphraseSalt
    });
    results = await request.send({ 
        host: "localhost",
        port: 4000,
        path: "/authenticate",
        method: "GET",
        headers: { 
            username: "marchuanv",
            fromhost: "localhost",
            fromport: 6000,
            passphrase: "secure1"
        }, 
        data: "",
        retryCount: 1
    });
    if (results.statusCode !== 401){
        throw "Secure With Incorrect Password Different Port Test Failed";
    }

    //Unsecure
    await requestHandlerSecure.handle("blabla",{
        host: "localhost",
        port: 5000,
        path: "/test"
    });



})().catch((err)=>{
    console.error(err);
});