const requestHandlerUnsecure = require("./component.request.handler.unsecure.js");
const requestUnsecure = require("component.request.unsecure");
const delegate = require("component.delegate");
const logging = require("logging");
logging.config.add("Request Handler Secure");

( async() => {

    let newRequest = { name: "localhost", port: 3000, path: "/test" };
    const name = `${newRequest.port}${newRequest.path}`;
    delegate.register("blabla", name, () => {
        return { statusCode: 200, statusMessage: "Success", headers: {}, data: "blabla did something" };
    });

    //Unsecure Handler
    await requestHandlerUnsecure.handle("blabla",{
        host: newRequest.name,
        port: newRequest.port,
        path: newRequest.path,
        hashedPassphrase: null,
        hashedPassphraseSalt: null
    });

    //Unsecure Request
    let results = await requestUnsecure.send({ 
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

    process.exit();

})().catch((err)=>{
    console.error(err);
    process.exit();
});