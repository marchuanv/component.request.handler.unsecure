const requestHandlerUser = require("component.request.handler.user");
const delegate = require("component.delegate");

module.exports = {
    handle: (context, options) => {
        const name = `${options.port}${options.path}`;
        requestHandlerUser.handle(context, options);
        delegate.register("component.request.handler.unsecure", name, async ({ session,  data }) => {
            return await delegate.call({ context, name }, { session, data });
        });
    }
};