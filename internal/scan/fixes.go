package scan

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Platforms are the fix targets, in display order.
var Platforms = []struct{ ID, Name string }{
	{"nginx", "nginx"}, {"apache", "Apache"}, {"caddy", "Caddy"},
	{"nextjs", "Next.js"}, {"vercel", "Vercel"}, {"netlify", "Netlify"},
}

var where = map[string]string{
	"nginx":   "nginx: inside the server { } block",
	"apache":  "Apache: virtual host or .htaccess",
	"caddy":   "Caddyfile: inside the site block",
	"nextjs":  "next.config.js",
	"vercel":  "vercel.json",
	"netlify": "netlify.toml",
}

// six builds one fix per platform, in Platforms order.
func six(snippets ...string) []Fix {
	fixes := make([]Fix, len(Platforms))
	for i, p := range Platforms {
		fixes[i] = Fix{p.ID, where[p.ID], snippets[i]}
	}
	return fixes
}

func anyFix(where, snippet string) []Fix { return []Fix{{"any", where, snippet}} }

// quote renders s as a double-quoted string that is valid in nginx, Apache,
// Caddy, JavaScript, JSON and TOML for the plain-ASCII values used here.
func quote(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

// lines formats one line per header and joins them.
func lines(pairs [][2]string, format, sep string) string {
	out := make([]string, len(pairs))
	for i, p := range pairs {
		out[i] = fmt.Sprintf(format, p[0], quote(p[1]))
	}
	return strings.Join(out, sep)
}

// headersFix returns the config that makes each platform send the given headers.
func headersFix(pairs [][2]string) []Fix {
	return six(
		"# add_header inside a location { } block replaces inherited headers,\n# so repeat these there if you use one.\n"+
			lines(pairs, "add_header %s %s always;", "\n"),
		"# needs mod_headers (a2enmod headers)\n"+lines(pairs, "Header always set %s %s", "\n"),
		lines(pairs, "header %s %s", "\n"),
		"module.exports = {\n  async headers() {\n    return [\n      {\n        source: '/(.*)',\n        headers: [\n"+
			lines(pairs, "          { key: '%s', value: %s },", "\n")+
			"\n        ],\n      },\n    ];\n  },\n};",
		"{\n  \"headers\": [\n    {\n      \"source\": \"/(.*)\",\n      \"headers\": [\n"+
			lines(pairs, "        { \"key\": \"%s\", \"value\": %s }", ",\n")+
			"\n      ]\n    }\n  ]\n}",
		"[[headers]]\n  for = \"/*\"\n  [headers.values]\n"+lines(pairs, "    %s = %s", "\n"),
	)
}

// withHeader marks f as fixed by sending one response header.
func withHeader(f Finding, name, value string) Finding {
	f.header = [2]string{name, value}
	f.Fixes = headersFix([][2]string{f.header})
	return f
}

const managedTLS = "Nothing to configure: this platform terminates TLS for you.\nIf this finding shows up anyway, the scan is probably reaching a proxy\nor CDN in front of the platform. Fix it there."

var tlsVersionFix = six(
	"ssl_protocols TLSv1.2 TLSv1.3;",
	"# needs mod_ssl\nSSLProtocol -all +TLSv1.2 +TLSv1.3",
	"# Caddy only accepts TLS 1.2 and 1.3 by default. To pin it explicitly:\ntls {\n    protocols tls1.2 tls1.3\n}",
	"Next.js does not terminate TLS. Change this on the reverse proxy,\nload balancer or host in front of it.",
	managedTLS, managedTLS,
)

var httpsRedirectFix = six(
	"# a separate server block for plain HTTP\nserver {\n    listen 80;\n    listen [::]:80;\n    server_name example.com;\n    return 301 https://$host$request_uri;\n}",
	"# in the port 80 virtual host; needs mod_rewrite\nRewriteEngine On\nRewriteCond %{HTTPS} off\nRewriteRule ^ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]",
	"# Caddy redirects HTTP to HTTPS automatically when the site address is a\n# plain domain. Make sure it is not written as http://example.com:\nexample.com {\n    # ...\n}",
	"Next.js does not handle this itself. Add the redirect on the reverse\nproxy or host in front of it.",
	"Nothing to configure: Vercel redirects HTTP to HTTPS automatically.\nIf this finding shows up, the scan is reaching something in front of Vercel.",
	"Netlify redirects HTTP to HTTPS once the site has a certificate.\nCheck Domain management > HTTPS in the site settings.",
)

var certFix = anyFix("Shell and web server config",
	"# Let's Encrypt with certbot: renew, then reload the web server\ncertbot renew\n\n# nginx: serve the full chain, not just your own certificate\nssl_certificate     /etc/letsencrypt/live/example.com/fullchain.pem;\nssl_certificate_key /etc/letsencrypt/live/example.com/privkey.pem;\n\n# Apache 2.4.8+\nSSLCertificateFile    /etc/letsencrypt/live/example.com/fullchain.pem\nSSLCertificateKeyFile /etc/letsencrypt/live/example.com/privkey.pem")

var cookieFix = six(
	"# nginx 1.19.3+, when proxying to your app\nproxy_cookie_flags ~ secure httponly samesite=lax;",
	"# needs mod_headers. Blunt: appends the flags to every cookie, so prefer\n# setting them in the application.\nHeader always edit Set-Cookie ^(.*)$ \"$1; Secure; HttpOnly; SameSite=Lax\"",
	"Caddy has no directive for cookie flags. Set them where the cookie is\ncreated, in your application:\n\nSet-Cookie: session=...; Path=/; Secure; HttpOnly; SameSite=Lax",
	"// in a Route Handler or Server Action\nimport { cookies } from 'next/headers';\n\n(await cookies()).set('session', value, {\n  secure: true,\n  httpOnly: true,\n  sameSite: 'lax',\n  path: '/',\n});",
	"Cookies come from your functions or framework, not from vercel.json.\nSet the flags where the cookie is created:\n\nSet-Cookie: session=...; Path=/; Secure; HttpOnly; SameSite=Lax",
	"Cookies come from your functions or framework, not from netlify.toml.\nSet the flags where the cookie is created:\n\nSet-Cookie: session=...; Path=/; Secure; HttpOnly; SameSite=Lax",
)

var disclosureFix = six(
	"server_tokens off;\n# when proxying to an app that adds its own banner\nproxy_hide_header X-Powered-By;",
	"# ServerTokens and ServerSignature go in the main server config\nServerTokens Prod\nServerSignature Off\n# needs mod_headers\nHeader always unset X-Powered-By",
	"header {\n    -Server\n    -X-Powered-By\n}",
	"module.exports = {\n  poweredByHeader: false,\n};",
	"The Server header is set by Vercel and cannot be removed.\nX-Powered-By comes from your framework. In Next.js, set\npoweredByHeader: false in next.config.js.",
	"The Server header is set by Netlify and cannot be removed.\nX-Powered-By comes from your framework or functions. Turn it off there.",
)

var exposedFix = six(
	"# 404 for every dotfile except /.well-known/\nlocation ~ /\\.(?!well-known/) {\n    return 404;\n}",
	"# needs mod_alias: 404 for every dotfile except /.well-known/\nRedirectMatch 404 \"/\\.(?!well-known/)\"",
	"@dotfiles {\n    path */.*\n    not path /.well-known/*\n}\nrespond @dotfiles 404",
	"Next.js only serves files under public/. Remove .git and .env from\npublic/ and make sure no rewrite exposes the project root.",
	"Vercel only serves your build output. Check the Output Directory setting\nand keep .git and .env files out of it.",
	"Netlify only serves the publish directory. Point it at your build output,\nnot the repository root, and keep .git and .env files out of it.",
)

const strictCSP = "default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self'; form-action 'self'"
