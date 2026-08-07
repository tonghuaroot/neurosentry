// Copyright 2025 NeuroSentry Contributors
// SPDX-License-Identifier: Apache-2.0

package web

import "net/http"

// handleOpenAPI serves the machine-readable OpenAPI 3.0 description of the API.
func (s *Server) handleOpenAPI(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(openAPISpec))
}

// handleDocs serves a self-contained (CSP-compliant, no CDN) API reference that
// renders the OpenAPI spec.
func (s *Server) handleDocs(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(docsHTML))
}

const openAPISpec = `{
  "openapi": "3.0.3",
  "info": {
    "title": "NeuroSentry API",
    "description": "eBPF runtime defense platform for AI inference. Multi-tenant control plane with RBAC.",
    "version": "0.2.0",
    "license": {"name": "Apache-2.0"}
  },
  "servers": [{"url": "/", "description": "Local agent"}],
  "components": {
    "securitySchemes": {
      "bearerAuth": {"type": "http", "scheme": "bearer", "bearerFormat": "JWT"},
      "apiKeyAuth": {"type": "apiKey", "in": "header", "name": "X-API-Key"}
    }
  },
  "paths": {
    "/api/health": {"get": {"summary": "Liveness probe", "tags": ["System"], "responses": {"200": {"description": "OK"}}}},
    "/api/status": {"get": {"summary": "Agent status, version, uptime", "tags": ["System"], "responses": {"200": {"description": "Status object"}}}},
    "/api/auth/login": {"post": {"summary": "Authenticate and obtain a JWT", "tags": ["Auth"], "requestBody": {"required": true, "content": {"application/json": {"schema": {"type": "object", "properties": {"tenant_slug": {"type": "string"}, "email": {"type": "string"}, "password": {"type": "string"}, "api_key": {"type": "string"}, "provider": {"type": "string"}}}}}}, "responses": {"200": {"description": "Token + principal"}, "401": {"description": "Invalid credentials"}}}},
    "/api/auth/me": {"get": {"summary": "Current principal", "tags": ["Auth"], "security": [{"bearerAuth": []}, {"apiKeyAuth": []}], "responses": {"200": {"description": "Principal"}, "401": {"description": "Unauthenticated"}}}},
    "/api/tenants": {
      "get": {"summary": "List tenants (system admin)", "tags": ["Tenants"], "security": [{"bearerAuth": []}], "responses": {"200": {"description": "Tenant list"}, "403": {"description": "Forbidden"}}},
      "post": {"summary": "Create tenant (system admin)", "tags": ["Tenants"], "security": [{"bearerAuth": []}], "responses": {"201": {"description": "Created"}, "409": {"description": "Conflict"}}}
    },
    "/api/tenants/{id}/users": {
      "get": {"summary": "List users in a tenant", "tags": ["Users"], "security": [{"bearerAuth": []}], "parameters": [{"name": "id", "in": "path", "required": true, "schema": {"type": "string"}}], "responses": {"200": {"description": "User list"}, "403": {"description": "Cross-tenant denied"}}},
      "post": {"summary": "Create a user in a tenant", "tags": ["Users"], "security": [{"bearerAuth": []}], "parameters": [{"name": "id", "in": "path", "required": true, "schema": {"type": "string"}}], "responses": {"201": {"description": "Created"}, "403": {"description": "Cross-tenant denied"}}}
    },
    "/api/users/{id}/apikeys": {"post": {"summary": "Issue an API key for a user (returned once)", "tags": ["Users"], "security": [{"bearerAuth": []}], "parameters": [{"name": "id", "in": "path", "required": true, "schema": {"type": "string"}}], "responses": {"201": {"description": "Raw API key"}}}},
    "/api/audit": {"get": {"summary": "Recent audit chain entries", "tags": ["Audit"], "responses": {"200": {"description": "Entries + chain validity"}}}},
    "/api/audit/verify": {"get": {"summary": "Verify audit hash chain integrity", "tags": ["Audit"], "responses": {"200": {"description": "Verification result"}}}},
    "/api/audit/export": {"get": {"summary": "Export the full audit chain as JSON", "tags": ["Audit"], "responses": {"200": {"description": "Downloadable audit export"}}}},
    "/api/mcp/stats": {"get": {"summary": "MCP interception statistics", "tags": ["MCP"], "responses": {"200": {"description": "Stats"}}}},
    "/api/mcp/events": {"get": {"summary": "Recent MCP tool-call decisions", "tags": ["MCP"], "responses": {"200": {"description": "Events"}}}},
    "/api/events/stream": {"get": {"summary": "Server-sent event stream of live events", "tags": ["Events"], "responses": {"200": {"description": "text/event-stream"}}}}
  }
}`

const docsHTML = `<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>NeuroSentry API Reference</title>
<style>
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#0a0e17;color:#c8d6e5;margin:0;padding:24px;line-height:1.5}
h1{color:#00e5ff;font-size:22px}h2{color:#4488ff;font-size:14px;text-transform:uppercase;letter-spacing:1px;margin-top:24px;border-bottom:1px solid #1a2744;padding-bottom:4px}
.ep{display:flex;gap:10px;align-items:baseline;padding:6px 0;border-bottom:1px solid #111a2e}
.m{font-family:monospace;font-weight:700;font-size:11px;padding:2px 8px;border-radius:3px;min-width:44px;text-align:center}
.get{background:#064e3b;color:#34d399}.post{background:#1e3a5f;color:#60a5fa}
.path{font-family:monospace;color:#e8f0ff}.sum{color:#5a7a9a;font-size:13px}
.sec{color:#ffaa00;font-size:10px;margin-left:auto}
a{color:#00e5ff}
</style></head><body>
<h1>NeuroSentry API Reference</h1>
<p class="sum">Machine-readable spec: <a href="/api/openapi.json">/api/openapi.json</a> (OpenAPI 3.0)</p>
<div id="root"></div>
<script>
fetch('/api/openapi.json').then(r=>r.json()).then(spec=>{
const root=document.getElementById('root');
const tags={};
for(const[path,methods]of Object.entries(spec.paths)){
for(const[method,op]of Object.entries(methods)){
const tag=(op.tags&&op.tags[0])||'Other';
(tags[tag]=tags[tag]||[]).push({method,path,op});
}}
for(const[tag,eps]of Object.entries(tags)){
const h=document.createElement('h2');h.textContent=tag;root.appendChild(h);
eps.forEach(e=>{
const d=document.createElement('div');d.className='ep';
const m=document.createElement('span');m.className='m '+e.method;m.textContent=e.method.toUpperCase();
const p=document.createElement('span');p.className='path';p.textContent=e.path;
const s=document.createElement('span');s.className='sum';s.textContent=e.op.summary||'';
d.appendChild(m);d.appendChild(p);d.appendChild(s);
if(e.op.security){const sec=document.createElement('span');sec.className='sec';sec.textContent='AUTH';d.appendChild(sec);}
root.appendChild(d);
});}
});
</script></body></html>`
