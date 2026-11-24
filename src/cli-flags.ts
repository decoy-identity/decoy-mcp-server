/**
 * `--version` and `--help`: answered before anything else in the entrypoint (src/index.ts), so a
 * probe of the package gets its answer and exits 0 without starting the bridge, opening a browser,
 * pairing or reading a setting.
 */

const VERSION_FLAGS = ['--version', '-v'];
const HELP_FLAGS = ['--help', '-h'];

/** The usage text: every flag the entrypoint reads. */
export function helpText(version: string): string {
  return [
    `decoy-mcp-server ${version}`,
    'Local bridge to Decoy: shared memory, account logins, email aliases and codes. Decrypts here.',
    '',
    'Usage: npx decoy-mcp-server [options]',
    '       npx decoy-mcp-server call <tool> [<json> | - | @file] [--json]',
    '       npx decoy-mcp-server tools [<tool>] [--json]',
    '       npx decoy-mcp-server run [--env NAME=<ref>]... [--env-file <file>]',
    '           [--aws <host|account-id>] -- <command> [args...]',
    'No option: serve /mcp on loopback, port 3001 (DECOY_MCP_PORT or PORT sets it).',
    'No saved connection: open decoys.me/connect to pair with the Decoy app.',
    '  --no-browser      pair without a browser; print the pairing link and code as JSON',
    '  --stdio           serve MCP on standard input and output',
    '  --reconnect       check the saved connection; pair with the same key only if it does not work',
    '  --new-pairing     pair again with the same key even when the saved connection works',
    "  --logout          revoke this bridge's token and delete its files in ~/.decoy",
    '  --import <file>   import memories from a mem0 export, MCP Memory memory.jsonl or a text list',
    '  --context         print what Decoy holds about you and the two habits, then exit',
    '  --full            with --context: also print the memory rules',
    '  --version, -v     print the version and exit',
    '  --help, -h        print this help and exit',
    '  --json            with call or tools: print JSON instead of text',
    '  --env NAME=<ref>  with run: resolve a decoy:// reference into an env variable (repeatable)',
    '  --env-file <file> with run: read NAME=value lines; resolve references; # starts a comment',
    '  --aws <host|id>   with run: give the command one-hour AWS STS credentials',
    '  call <tool>       call once with the saved connection; JSON args, - for stdin, or @file',
    '  tools [<tool>]    list tools and arguments, or one tool whole; needs no connection',
    '  run              give a command secrets in its environment; mask output; use current grants',
    "  hook <event>      session-start, prompt, stop or pre-tool lifecycle hook (with --host)",
    'Documentation: https://decoys.me/documentation',
    '',
  ].join('\n');
}

/** What `--version` or `--help` prints, or null when neither is given. Either one wins over every
 *  other flag; `--help` wins over `--version`. */
export function cliAnswer(args: readonly string[], version: string): string | null {
  if (args.some((a) => HELP_FLAGS.includes(a))) return helpText(version);
  if (args.some((a) => VERSION_FLAGS.includes(a))) return `${version}\n`;
  return null;
}
