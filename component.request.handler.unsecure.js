const component = require("component");
component.register({ moduleName: "component.request.handler.unsecure" }).then( async ({ requestHandlerUnsecure }) => {
    const { config } = await component.load({ moduleName: "component.request.handler.route" });
    const { routes, port } = config.requestHandlerRoute;
    for(const route of routes){
        if (route.secure === false){
            const name = `${port}${route.path}`;
            requestHandlerUnsecure.subscribe( { name }, async ({ session, data }) => {
                return await requestHandlerUnsecure.publish({ name }, { session, data });
            });
        }
    };
});