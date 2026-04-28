/**
 * Construct and run the plugin using process.stdin/stdout.
 */
export function run({ env, stdin, stdout }?: {
    env?: any;
    stdin?: any;
    stdout?: any;
}): Promise<void>;
/**
 * Build the per-request handler. Exposed for unit tests so we can feed
 * crafted input messages without spinning up readline/stdin.
 *
 * @returns {(req:any) => Promise<{id:any, action:string, msg?:string}>}
 */
export function makeHandler({ config, resolver, verifiedAuthors, logger }: {
    config: any;
    resolver: any;
    verifiedAuthors: any;
    logger: any;
}): (req: any) => Promise<{
    id: any;
    action: string;
    msg?: string;
}>;
/**
 * Pull the `nip05` string out of a kind:0 event's content.
 */
export function extractNip05(content: any): string | null;
