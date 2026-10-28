import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';

/** `server.registerTool`, registering only the tools `include` allows (all when it is absent). */
export function gatedRegister(server: McpServer, include?: (tool: string) => boolean): McpServer['registerTool'] {
  return ((name: string, ...rest: unknown[]) =>
    (include?.(name) ?? true) ? (server.registerTool as (...a: unknown[]) => unknown)(name, ...rest) : undefined) as McpServer['registerTool'];
}
