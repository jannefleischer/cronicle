// Cronicle OIDC Bridge Mixin
// Connects Cronicle to a Keycloak (or compatible) OIDC IdP
// via the pixl-server-user external_user_api mechanism.
//
// Config block (in conf/config.json):
// "oidc": {
//   "enabled": true,
//   "issuer": "https://keycloak.host/realms/myrealm",
//   "client_id": "cronicle",
//   "client_secret": "SECRET",
//   "callback_url": "https://cronicle.host/oidc/callback",
//   "scope": "openid profile email",
//   "admin_roles": ["cronicle-admin"],
//   "https_verify": true,
//   "cookie_max_age": 86400
// }

'use strict';

var https = require('https');
var Request = require('pixl-request');

var Class = require('pixl-class');

module.exports = Class.create({

	oidc_startup: function() {
		// Initialise OIDC bridge if enabled. Called from engine startup().
		var self = this;
		var oidc = this.server.config.get('oidc');
		if (!oidc || !oidc.enabled) return;

		if (!oidc.issuer || !oidc.client_id || !oidc.client_secret || !oidc.callback_url) {
			this.logError('oidc', "OIDC is enabled but missing required config (issuer, client_id, client_secret, callback_url)");
			return;
		}

		this.logDebug(3, "OIDC bridge initializing", {
			issuer: oidc.issuer,
			client_id: oidc.client_id,
			callback_url: oidc.callback_url
		});

		// Dedicated HTTP client for Keycloak calls
		this.oidcRequest = new Request('CronicleOIDC/1.0');
		this.oidcRequest.setFollow(2);

		if (oidc.https_verify === false) {
			this.logDebug(3, "OIDC: TLS verification disabled (https_verify=false)");
			this.oidcSSLAgent = new https.Agent({ rejectUnauthorized: false });
		}

		// Derive the bridge URL from config or base_app_url
		var base = oidc.base_url || this.server.config.get('base_app_url') || '';
		var bridge_url = oidc.bridge_url || (base + '/oidc/bridge');

		// Wire up the pixl-server-user external_user_api to our bridge
		this.usermgr.config.set('external_user_api', bridge_url);
		this.logDebug(4, "OIDC: external_user_api set to: " + bridge_url);

		// Register URI handlers on the web server
		this.web.addURIHandler('/oidc/bridge',    'OIDC Bridge',    this.handle_oidc_bridge.bind(this));
		this.web.addURIHandler('/oidc/callback',  'OIDC Callback',  this.handle_oidc_callback.bind(this));

		this.logDebug(3, "OIDC bridge ready");
	},

	// -------------------------------------------------------------------------
	// /oidc/bridge
	// Called server-to-server by pixl-server-user (api_external_login) to
	// check if the user has a valid Keycloak session (via the refresh_token
	// stored in an HttpOnly cookie). Also handled as a browser redirect target
	// for logout (?logout=1).
	// -------------------------------------------------------------------------
	handle_oidc_bridge: function(args, callback) {
		var self = this;
		var oidc = this.server.config.get('oidc');
		var query = args.query || {};

		// Browser-initiated logout: redirect to Keycloak end-session endpoint
		if (query.logout) {
			var base = oidc.base_url || this.server.config.get('base_app_url') || '/';
			var logout_url = oidc.issuer +
				'/protocol/openid-connect/logout' +
				'?client_id=' + encodeURIComponent(oidc.client_id) +
				'&post_logout_redirect_uri=' + encodeURIComponent(base);

			this.logDebug(6, "OIDC: logout redirect → " + logout_url);
			// Clear the OIDC session cookie on the way out
			callback("302 Found", {
				'Location': logout_url,
				'Set-Cookie': 'cronicle_oidc=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0'
			}, "");
			return;
		}

		// Extract the refresh_token stored as an HttpOnly cookie
		var cookies = this.oidc_parse_cookies(args.request.headers.cookie || '');
		var refresh_token = cookies['cronicle_oidc'];

		if (!refresh_token) {
			// No OIDC session → redirect browser to Keycloak login
			return this.oidc_return_login_redirect(oidc, callback);
		}

		// Exchange the refresh_token for a fresh access_token, then call userinfo
		this.oidc_refresh_and_userinfo(refresh_token, oidc, function(err, userinfo, new_rt) {
			if (err || !userinfo) {
				self.logDebug(5, "OIDC: session validation failed (" + (err ? err.message : 'no userinfo') + "), redirecting to login");
				return self.oidc_return_login_redirect(oidc, callback);
			}

			var username = self.oidc_normalize_username(userinfo);
			var resp = {
				code: 0,
				username: username,
				user: {
					full_name: userinfo.name || userinfo.preferred_username || username,
					email: userinfo.email || '',
					privileges: self.oidc_get_privileges(userinfo, oidc)
				}
			};

			self.logDebug(6, "OIDC: session valid for user: " + username, { email: resp.user.email });

			var headers = { 'Content-Type': 'application/json' };

			// Rotate the cookie when Keycloak issues a new refresh_token
			if (new_rt && new_rt !== refresh_token) {
				headers['Set-Cookie'] = 'cronicle_oidc=' + encodeURIComponent(new_rt) +
					'; Path=/; HttpOnly; SameSite=Lax; Max-Age=' + (oidc.cookie_max_age || 86400);
			}

			callback("200 OK", headers, JSON.stringify(resp));
		});
	},

	// -------------------------------------------------------------------------
	// /oidc/callback
	// Keycloak redirects here after successful authentication.
	// Exchanges the authorization code for tokens, stores the refresh_token
	// in an HttpOnly cookie, then redirects the browser back to Cronicle.
	// -------------------------------------------------------------------------
	handle_oidc_callback: function(args, callback) {
		var self = this;
		var oidc = this.server.config.get('oidc');
		var query = args.query || {};

		// Keycloak reported an error
		if (query.error) {
			var desc = query.error_description || query.error;
			this.logError('oidc', "Keycloak auth error: " + desc);
			callback("400 Bad Request", { 'Content-Type': 'text/plain' },
				"Authentication failed: " + desc);
			return;
		}

		if (!query.code) {
			// No code, just redirect home
			callback("302 Found", { 'Location': '/' }, "");
			return;
		}

		// Recover the Cronicle return URL from the state parameter.
		// pixl-server-user appended encodeURIComponent(returnUrl) after our
		// "cronicle_return%3D" marker, so the decoded state looks like:
		//   cronicle_return=http%3A%2F%2Flocalhost%3A3012%2F
		var state = query.state || '';
		var return_url = '/';
		var prefix = 'cronicle_return=';
		if (state.indexOf(prefix) === 0) {
			try { return_url = decodeURIComponent(state.slice(prefix.length)); }
			catch(e) { return_url = '/'; }
		}

		// Validate that the return URL is a relative path or matches the configured base
		var base = oidc.base_url || this.server.config.get('base_app_url') || '';
		if (return_url !== '/' && base && !return_url.startsWith(base) && !return_url.startsWith('/')) {
			this.logDebug(5, "OIDC: suspicious return_url, resetting to /: " + return_url);
			return_url = '/';
		}

		this.logDebug(7, "OIDC: callback received, return_url=" + return_url);

		// Exchange auth code for tokens
		this.oidc_exchange_code(query.code, oidc, function(err, tokens) {
			if (err || !tokens || !tokens.refresh_token) {
				self.logError('oidc', "Token exchange failed: " + (err ? err.message : 'no refresh_token in response'));
				callback("500 Internal Server Error", { 'Content-Type': 'text/plain' },
					"OIDC authentication error. Please try again or contact an administrator.");
				return;
			}

			self.logDebug(6, "OIDC: code exchange successful, setting session cookie");

			callback("302 Found", {
				'Set-Cookie': 'cronicle_oidc=' + encodeURIComponent(tokens.refresh_token) +
					'; Path=/; HttpOnly; SameSite=Lax; Max-Age=' + (oidc.cookie_max_age || 86400),
				'Location': return_url
			}, "");
		});
	},

	// -------------------------------------------------------------------------
	// Internal helpers
	// -------------------------------------------------------------------------

	// Return JSON instruction to the browser that triggers a Keycloak auth redirect.
	// pixl-server-user appends encodeURIComponent(returnUrl) to this URL string,
	// which becomes the tail of our state parameter → recovered in the callback.
	oidc_return_login_redirect: function(oidc, callback) {
		var url = oidc.issuer + '/protocol/openid-connect/auth' +
			'?client_id='     + encodeURIComponent(oidc.client_id) +
			'&redirect_uri='  + encodeURIComponent(oidc.callback_url) +
			'&response_type=code' +
			'&scope='         + encodeURIComponent(oidc.scope || 'openid profile email') +
			'&state=cronicle_return%3D'; // pixl-server-user appends the encoded return URL here

		callback("200 OK", { 'Content-Type': 'application/json' },
			JSON.stringify({ code: 0, location: url }));
	},

	// Use a stored refresh_token to get a fresh access_token and then call userinfo.
	oidc_refresh_and_userinfo: function(refresh_token, oidc, done) {
		var self = this;
		var token_url = oidc.issuer + '/protocol/openid-connect/token';
		var body = [
			'grant_type=refresh_token',
			'refresh_token=' + encodeURIComponent(refresh_token),
			'client_id='     + encodeURIComponent(oidc.client_id),
			'client_secret=' + encodeURIComponent(oidc.client_secret)
		].join('&');

		var req_opts = { timeout: 10000, headers: { 'Content-Type': 'application/x-www-form-urlencoded' } };
		if (self.oidcSSLAgent) req_opts.agent = self.oidcSSLAgent;

		self.oidcRequest.post(token_url, body, req_opts, function(err, resp, data) {
			if (err) return done(new Error("Token refresh HTTP error: " + err.message));
			if (resp.statusCode !== 200) {
				return done(new Error("Token refresh failed: HTTP " + resp.statusCode));
			}

			var tokens;
			try { tokens = JSON.parse(data.toString()); }
			catch(e) { return done(new Error("Token refresh JSON parse error: " + e.message)); }

			var access_token = tokens.access_token;
			if (!access_token) return done(new Error("No access_token in refresh response"));

			var userinfo_url = oidc.issuer + '/protocol/openid-connect/userinfo';
			var ui_opts = { timeout: 5000, headers: { 'Authorization': 'Bearer ' + access_token } };
			if (self.oidcSSLAgent) ui_opts.agent = self.oidcSSLAgent;

			self.oidcRequest.get(userinfo_url, ui_opts, function(err, resp, data) {
				if (err) return done(new Error("Userinfo HTTP error: " + err.message));
				if (resp.statusCode !== 200) {
					return done(new Error("Userinfo failed: HTTP " + resp.statusCode));
				}

				var userinfo;
				try { userinfo = JSON.parse(data.toString()); }
				catch(e) { return done(new Error("Userinfo JSON parse error: " + e.message)); }

				done(null, userinfo, tokens.refresh_token || refresh_token);
			});
		});
	},

	// Exchange an authorization code for tokens at the token endpoint.
	oidc_exchange_code: function(code, oidc, done) {
		var self = this;
		var token_url = oidc.issuer + '/protocol/openid-connect/token';
		var body = [
			'grant_type=authorization_code',
			'code='         + encodeURIComponent(code),
			'redirect_uri=' + encodeURIComponent(oidc.callback_url),
			'client_id='    + encodeURIComponent(oidc.client_id),
			'client_secret='+ encodeURIComponent(oidc.client_secret)
		].join('&');

		var req_opts = { timeout: 10000, headers: { 'Content-Type': 'application/x-www-form-urlencoded' } };
		if (self.oidcSSLAgent) req_opts.agent = self.oidcSSLAgent;

		self.oidcRequest.post(token_url, body, req_opts, function(err, resp, data) {
			if (err) return done(new Error("Code exchange HTTP error: " + err.message));
			if (resp.statusCode !== 200) {
				return done(new Error("Code exchange failed: HTTP " + resp.statusCode + " " + (data ? data.toString().slice(0, 200) : '')));
			}

			var tokens;
			try { tokens = JSON.parse(data.toString()); }
			catch(e) { return done(new Error("Code exchange JSON parse error: " + e.message)); }

			done(null, tokens);
		});
	},

	// Normalize a Keycloak preferred_username to a Cronicle-safe username.
	// Cronicle requires: /^[\w\-\.]+$/
	oidc_normalize_username: function(userinfo) {
		var raw = userinfo.preferred_username || userinfo.sub || userinfo.email || 'unknown';
		// Drop email domain (e.g. user@company.com → user)
		raw = raw.replace(/@.+$/, '');
		// Replace any character not in [\w\-\.] with underscore
		return raw.toLowerCase().replace(/[^\w\-\.]/g, '_');
	},

	// Map Keycloak realm / client roles to Cronicle privileges.
	oidc_get_privileges: function(userinfo, oidc) {
		var realm_roles  = (userinfo.realm_access && userinfo.realm_access.roles) || [];
		var client_roles = (userinfo.resource_access &&
		                    userinfo.resource_access[oidc.client_id] &&
		                    userinfo.resource_access[oidc.client_id].roles) || [];
		var all_roles    = realm_roles.concat(client_roles);

		var admin_roles = oidc.admin_roles || ['admin', 'cronicle-admin'];
		var is_admin    = admin_roles.some(function(r) { return all_roles.indexOf(r) >= 0; });

		return is_admin ? { admin: 1 } : {};
	},

	// Parse the Cookie header into a plain object.
	oidc_parse_cookies: function(cookie_header) {
		var cookies = {};
		(cookie_header || '').split(';').forEach(function(part) {
			var idx = part.indexOf('=');
			if (idx > 0) {
				var key = part.slice(0, idx).trim();
				var val = part.slice(idx + 1).trim();
				try { cookies[key] = decodeURIComponent(val); }
				catch(e) { cookies[key] = val; }
			}
		});
		return cookies;
	}

}); // module.exports
