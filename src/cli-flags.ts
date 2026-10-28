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
    'The local MCP bridge to Decoy: the memory your agents share, and your account logins,',
    'email aliases and codes. It decrypts on this machine.',
    '',
    'Usage: npx decoy-mcp-server [options]',
    '       npx decoy-mcp-server call <tool> [<json> | - | @file] [--json]',
    '       npx decoy-mcp-server tools [<tool>] [--json]',
    '',
    'With no option it starts the bridge on this computer only, at /mcp on port 3001 (DECOY_MCP_PORT',
    'or PORT sets the port). With no saved connection it first opens decoys.me/connect to pair with',
    'the Decoy app.',
    '',
    'Options:',
    '  --no-browser      pair without opening a browser: print the pairing link and code as JSON',
    '  --reconnect       pair again with the same key, without revoking, so the app offers Reconnect',
    "  --logout          revoke this bridge's token and delete the files it made in ~/.decoy",
    '  --import <file>   bring memories from a mem0 export, an MCP Memory memory.jsonl or a text list',
    '  --context         print what Decoy holds about you and the two habits, then exit',
    '  --full            with --context: also print the memory rules',
    '  --version, -v     print the version and exit',
    '  --help, -h        print this help and exit',
    '',
    'Without a running server:',
    '  call <tool>       run one tool call with the saved connection, print its result and exit;',
    '                    the arguments are one JSON object, `-` for standard input, or @file',
    '  tools [<tool>]    list the tools and their arguments, or one tool whole',
    '  --json            with call or tools: print JSON instead of text',
    '',
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
