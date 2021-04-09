const component = require("component");
component.load(module).then(async ({ requestHandlerUnsecure }) => {
    requestHandlerUnsecure.subscribe(async ({ session, data }) => {
        return await requestHandlerUnsecure.publish({ session, data });
    });
});