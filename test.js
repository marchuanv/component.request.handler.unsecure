const requestHandlerSecure = require("./component.request.handler.secure.js");
const requestSecure = require("component.request.secure");
const requestUnsecure = require("component.request.unsecure");
const utils = require("utils");
const delegate = require("component.delegate");
const logging = require("logging");
logging.config.add("Request Handler Secure");

( async() => {

    //Secure Handler
    let { hashedPassphrase, hashedPassphraseSalt } = utils.hashPassphrase("secure1");
    let newRequest = { name: "localhost", port: 3000, path: "/test" };
    const name = `${newRequest.port}${newRequest.path}`;
    delegate.register("blabla", name, () => {
        return { statusCode: 200, statusMessage: "Success", headers: {}, data: "blabla did something" };
    });
    await requestHandlerSecure.handle("blabla",{
        host: newRequest.name,
        port: newRequest.port,
        path: newRequest.path,
        hashedPassphrase,
        hashedPassphraseSalt
    });

    //Secure Request New User
    let results = await requestSecure.send({
        host: newRequest.name,
        port: newRequest.port,
        path: newRequest.path,
        method: "GET",
        username: "marchuanv",
        fromhost: "localhost",
        fromport: 6000,
        passphrase: "secure1",
        data: "some blabla data"
    });
    if (results.statusCode !== 200 && results.statusMessage === "Authorised"){
        throw "Secure Request With Correct Password Test Failed";
    }

    //Secure Request Same User
    results = await requestSecure.send({ 
        host: newRequest.name,
        port: newRequest.port,
        path: newRequest.path,
        method: "GET",
        username: "marchuanv",
        data: "some more blabla data"
    });
    if (results.statusCode !== 200){
        throw "Secure Request With Correct Password Test Failed";
    }

    //Unsecure Handler
    await requestHandlerSecure.handle("blabla",{
        host: newRequest.name,
        port: newRequest.port,
        path: newRequest.path,
        hashedPassphrase: null,
        hashedPassphraseSalt: null
    });

    //Unsecure Request
    results = await requestUnsecure.send({ 
        host: newRequest.name,
        port: newRequest.port,
        path: newRequest.path,
        method: "GET",
        username: "marchuanv",
        fromhost: "localhost",
        fromport: 6000,
        data: ""
    });
    if (results.statusCode !== 200){
        throw "Secure With Incorrect Password Different Port Test Failed";
    }

    //process.exit();

})().catch((err)=>{
    console.error(err);
    process.exit();
});