const requestHandlerSecure = require("./component.request.handler.secure.js");
const delegate = require("component.delegate");
const request = require("component.request");
const utils = require("utils");
const logging = require("logging");
logging.config.add("Request Handler Secure");
( async() => {

    //Secure Handler
    let { hashedPassphrase, hashedPassphraseSalt } = utils.hashPassphrase("secure1");
    await requestHandlerSecure.handle("blabla",{
        host: "localhost",
        port: 3000,
        path: "/test",
        hashedPassphrase,
        hashedPassphraseSalt
    });
    //Secure Request With Correct Password
    let results = await request.send({ 
        host: "localhost",
        port: 3000,
        path: "/test",
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
        throw "Secure Request With Correct Password Test Failed";
    }
    //Secure Request With Incorrect Password
    results = await request.send({ 
        host: "localhost",
        port: 3000,
        path: "/test",
        method: "GET",
        headers: { 
            username: "marchuanv",
            fromhost: "localhost",
            fromport: 6000,
            passphrase: "secure2"
        }, 
        data: "",
        retryCount: 1
    });
    if (results.statusCode !== 401){
        throw "Secure Request With Incorrect Password Test Failed";
    }

    //Unsecure Handler
    await requestHandlerSecure.handle("blabla",{
        host: "localhost",
        port: 3000,
        path: "/test",
        hashedPassphrase: null,
        hashedPassphraseSalt: null
    });

    //Unsecure Request
    results = await request.send({ 
        host: "localhost",
        port: 3000,
        path: "/test",
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
        throw "Secure With Incorrect Password Different Port Test Failed";
    }

    process.exit();

})().catch((err)=>{
    console.error(err);
    process.exit();
});