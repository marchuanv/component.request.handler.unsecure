const requestHandler = require("./component.request.handler.secure.js");
const delegate = require("component.delegate");
const utils = require("utils");
(async()=>{ 
    const callingModule = "something";
    delegate.register(callingModule, (callback) => {
        return { statusCode: 200, statusMessage: "Success", headers: {}, data: null };
    });
    const { hashedPassphrase, salt } = utils.hashPassphrase("secure1");
    await requestHandler.handle(callingModule, {
        privatePort: 3000, 
        path: "/test", 
        publicHost: "localhost", 
        publicPort: 4000,
        username: "admin",
        hashedPassphrase,
        hashedPassphraseSalt: salt,
        fromhost: "somedomain",
        fromport: 6000
    });
})().catch((err)=>{
    console.error(err);
});