import OAuthProvider, { type OAuthHelpers } from "@cloudflare/workers-oauth-provider";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { McpAgent } from "agents/mcp";
import { Hono } from "hono";
import { authorize, callback, confirmConsent, tokenExchangeCallback } from "./auth";
import type { UserProps } from "./types";

export class AuthenticatedMCP extends McpAgent<Env, Record<string, never>, UserProps> {
	server = new McpServer({
		name: "Auth0 OIDC Proxy Demo",
		version: "1.0.0",
	});

	async init() {
		// No local tools are registered here. /mcp traffic is proxied to the upstream MCP server.
	}
}

type ProxyBindings = Env & {
	CF_ACCESS_CLIENT_ID?: string;
	CF_ACCESS_CLIENT_SECRET?: string;
};

const mcpProxyHandler = {
	async fetch(request: Request, env: any) {
		const { API_BASE_URL, CF_ACCESS_CLIENT_ID, CF_ACCESS_CLIENT_SECRET } = env as ProxyBindings;
		const incomingUrl = new URL(request.url);
		const upstreamUrl = new URL(incomingUrl.pathname + incomingUrl.search, API_BASE_URL);
		const hasCfServiceToken = Boolean(CF_ACCESS_CLIENT_ID && CF_ACCESS_CLIENT_SECRET);

		const forwardedHeaders = new Headers();
		request.headers.forEach((value, key) => {
			const lowerKey = key.toLowerCase();
			if (
				lowerKey === "host" ||
				lowerKey === "content-length" ||
				lowerKey === "authorization" ||
				lowerKey === "origin"
			) {
				return;
			}

			forwardedHeaders.set(key, value);
		});

		if (hasCfServiceToken) {
			forwardedHeaders.set("CF-Access-Client-Id", CF_ACCESS_CLIENT_ID);
			forwardedHeaders.set("CF-Access-Client-Secret", CF_ACCESS_CLIENT_SECRET);
		}

		console.log(
			"[mcp-proxy] forwarding",
			request.method,
			upstreamUrl.href,
			"session",
			request.headers.get("mcp-session-id") ?? "none",
			"cf_access_headers",
			hasCfServiceToken ? "injected" : "missing",
		);

		const body =
			request.method === "GET" || request.method === "HEAD"
				? undefined
				: await request.arrayBuffer();

		const upstreamResponse = await fetch(upstreamUrl.href, {
			method: request.method,
			headers: forwardedHeaders,
			body,
			redirect: "manual",
		});

		console.log("[mcp-proxy] upstream status", upstreamResponse.status, upstreamResponse.statusText);
		if (upstreamResponse.status >= 300 && upstreamResponse.status < 400) {
			console.log("[mcp-proxy] upstream redirect location", upstreamResponse.headers.get("location"));
		}

		return new Response(upstreamResponse.body, {
			headers: upstreamResponse.headers,
			status: upstreamResponse.status,
			statusText: upstreamResponse.statusText,
		});
	},
};

// Initialize the Hono app with the routes for the OAuth Provider.
const app = new Hono<{ Bindings: Env & { OAUTH_PROVIDER: OAuthHelpers } }>();
app.get("/authorize", authorize);
app.post("/authorize", confirmConsent);
app.get("/callback", callback);

export default new OAuthProvider({
	apiHandler: mcpProxyHandler,
	apiRoute: "/mcp",
	authorizeEndpoint: "/authorize",
	clientRegistrationEndpoint: "/register",
	// @ts-expect-error
	defaultHandler: app,
	tokenEndpoint: "/token",
	tokenExchangeCallback,
});
