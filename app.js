const Koa = require("koa");
const cors = require("@koa/cors");
const koaProxies = require("koa-proxies");
const Router = require("@koa/router");
const app = new Koa();
const router = new Router();
const requestIp = require('request-ip');
const url = require('url');

app.use(cors());

app.use(
    koaProxies("/fpjscdn", {
        target: "https://fpjscdn.net",
        rewrite: path => path.replace(/^\/fpjscdn(\/|\/\w+)?$/, '/v3/9LPPFowgE7CqfuxXzBNq'),
        changeOrigin: true,
        logs: true
    })
);

app.use(koaProxies('/fpjs', {
    target: "https://api.fpjs.io",
    rewrite: (path) => {
        // path => /fpjs?ci=js/3.8.12&ii=fingerprintjs-pro-react/2.1.1/next/10.1.3&ii=fingerprintjs-pro-spa/0.6.0'
        // return => ?ci=js/3.8.12&ii=fingerprintjs-pro-react/2.1.1/next/10.1.3&ii=fingerprintjs-pro-spa/0.6.0
        const queryIndex = path.indexOf('?');
        return queryIndex === -1 ? '' : path.substring(queryIndex);
    },
    changeOrigin: true,
    logs: true,
    events: {
        proxyReq: (proxyReq, req, res) => {
            // Set the Remote-Client-IP header
            const remoteClientIP = requestIp.getClientIp(req);
            proxyReq.setHeader('Remote-Client-IP', remoteClientIP);
            
            // Filter the cookies
            const rawCookies = req.headers["cookie"];
            if (!rawCookies) {
                return;
            }

            // Note, only _iidt and _vid_t cookies are relevant for Fingerprinting
            // Go through and filter out all the un-needed cookies for security
            const splitCookies = rawCookies.split(';');
            const filteredSplitCookies = splitCookies.filter((cookie) => {
                return cookie.trim().startsWith('_iidt') || cookie.trim().startsWith('_vid_t');
            })
            const filteredCookies = filteredSplitCookies.join(';');
            proxyReq.setHeader('cookie', filteredCookies);
        },
        proxyRes: (proxyRes, req, res) => {
            // Set the cookie domain to be the request origin for first party cookies
            const origin = req.headers['origin'];
            if (!origin) { return; }

            const parsedOrigin = url.parse(origin, true);
            if (!parsedOrigin.host) { return; }

            // Iterate over all the set cookies and specifically look for _iidt and fix the domain entry
            // Note, there should only be one cookie set cookie ever, but iterating over just for safety
            const rawSetCookies = proxyRes.headers['set-cookie'];
            for (let i = 0; i < rawSetCookies.length; i++) {
                // Find the cookie that starts with _iidt
                if (rawSetCookies[i].trim().startsWith('_iidt')) {
                    const raw_iidtCookie = rawSetCookies[i];
                    let split_iidtCookie = raw_iidtCookie.split(';');

                    // Iterate over the sections of the cookie to find Domain entry
                    for (let j = 0; j < split_iidtCookie.length; j++) {
                        // Find the section of the cookie starting with Domain
                        if (split_iidtCookie[j].trim().startsWith('Domain')) {
                            // Update the Domain entry to be the parsedOrigin host
                            split_iidtCookie[j] = ' Domain=' + parsedOrigin.host;
                            const final_iidtCookie = split_iidtCookie.join(';');
                            proxyRes.headers['set-cookie'][i] = final_iidtCookie;
                            return;
                        }
                    }

                }
            }
        },
        error: (err, req, res) => {
          // Handle error
          console.log(err);
        },
      },
}));

router.get("/", (ctx, next) => {
    ctx.body = "Hello World";
});

app.use(router.routes());
app.use(router.allowedMethods());

const port = 3000;
app.listen(port);
console.log(`listening on port ${port}`);