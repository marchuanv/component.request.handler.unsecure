const component = require("component");
component.register(module).then( async ({ requestHandlerUnsecure }) => {
    const { channel } = requestHandlerUnsecure;
    requestHandlerUnsecure.subscribe( { channel }, async ({ session, data }) => {
        return await requestHandlerUnsecure.publish({ channel }, { session, data });
    });
});