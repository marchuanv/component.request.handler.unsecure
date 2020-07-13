const requestHandler = require("./component.request.handler.secure.js");
const delegate = require("component.delegate");
const utils = require("utils");
(async()=>{ 
    const callingModule = "something";
    delegate.register(callingModule, (callback) => {
        return { statusCode: 200, statusMessage: "Success", headers: {}, data: "" };
    });
    const { hashedPassphrase, hashedPassphraseSalt } = utils.hashPassphrase("secure1");
    
    await requestHandler.handle(callingModule, {
        privatePort: 3000, 
        path: "/test", 
        publicHost: "localhost", 
        publicPort: 3000,
        hashedPassphrase,
        hashedPassphraseSalt
    });

//    await requestHandler.handle(callingModule, {
//         privatePort: 3000, 
//         path: "/test", 
//         publicHost: "localhost", 
//         publicPort: 3000
//     });

})().catch((err)=>{
    console.error(err);
});