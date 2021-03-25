const component = require("component");
component.register(module).then( async ({ requestHandlerUnsecure }) => {
    const { requestHandlerRoute } = await component.register("component.request.handler.route");
    const { routes, port } = requestHandlerRoute;
    for(const route of routes){
        if (route.secure === false){
            const name = `${port}${route.path}`;
            requestHandlerUnsecure.subscribe( { name }, async ({ session, data }) => {
                return await requestHandlerUnsecure.publish({ name }, { session, data });
            });
        }
    };
});