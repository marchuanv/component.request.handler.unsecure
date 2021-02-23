const requestHandlerUser = require("component.request.handler.user");
const utils = require("utils");
const delegate = require("component.delegate");
const logging = require("logging");
logging.config.add("Request Handler Unsecure");

module.exports = { 
    handle: (context, options) => {
        const name = `${options.port}${options.path}`;
        requestHandlerUser.handle(context, options);
        delegate.register("component.request.handler.unsecure", name, async ({ session,  data }) => {
            return await delegate.call({ context, name }, { session, data });
        });
    }
};