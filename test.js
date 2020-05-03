const componentRequestHandler = require("./component.request.handler.secure.js");
const logging = require("logging");
logging.config(["Request Handler Secure","Request Handler"]);
(async()=>{
    (await componentRequestHandler.handle({ 
        publicHost: "localhost", 
        publicPort: 3000, 
        privatePort: 3000, 
        path: "/test",
        username: "admin"
    })).receive(({fromhost, fromport, data })=>{
        return {
            contentType: "text/html",
            data: "<html>HELLO</html>"
        };
    });
})().catch((err)=>{
    console.log(err);
});
