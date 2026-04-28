export class ElectrumXClient {
    /**
     * @param {object} opts
     * @param {string} opts.host
     * @param {number} [opts.port=50002]
     * @param {boolean} [opts.tls=true]
     * @param {string|null} [opts.certPinSha256]  hex-encoded SHA-256 of DER cert
     * @param {boolean} [opts.rejectUnauthorized]  override default (default: true unless pinning)
     * @param {number} [opts.timeoutMs=5000]
     * @param {number} [opts.retries=2]
     * @param {(level:string,...args:any[])=>void} [opts.logger]
     */
    constructor(opts?: {
        host: string;
        port?: number | undefined;
        tls?: boolean | undefined;
        certPinSha256?: string | null | undefined;
        rejectUnauthorized?: boolean | undefined;
        timeoutMs?: number | undefined;
        retries?: number | undefined;
        logger?: ((level: string, ...args: any[]) => void) | undefined;
    });
    host: string;
    useTls: boolean;
    port: number;
    certPinSha256: string | null;
    rejectUnauthorized: boolean;
    timeoutMs: number;
    retries: number | undefined;
    logger: (level: string, ...args: any[]) => void;
    /**
     * Resolve a Namecoin name to its current value + metadata.
     *
     * @param {string} name  e.g. "d/testls"
     * @returns {Promise<{name:string,value:string,txid:string,height:number,expires_in?:number,tip?:number}|null>}
     */
    nameShow(name: string): Promise<{
        name: string;
        value: string;
        txid: string;
        height: number;
        expires_in?: number;
        tip?: number;
    } | null>;
    /**
     * One full resolve cycle over a single connection.
     */
    _connectAndQuery(name: any): Promise<any>;
}
/**
 * Canonical script used by namecoin-ElectrumX to index name lookups:
 *   OP_NAME_UPDATE <push(name)> <push("")> OP_2DROP OP_DROP OP_RETURN
 *
 * @param {Buffer} nameBytes  ASCII-encoded name like "d/testls"
 * @returns {Buffer}
 */
export function buildNameIndexScript(nameBytes: Buffer): Buffer;
/**
 * Electrum protocol scripthash: SHA-256 → reverse bytes → hex.
 * @param {Buffer} script
 * @returns {string}
 */
export function electrumScriptHash(script: Buffer): string;
/**
 * Parse a NAME_* script and return {name, value}.
 *
 * Script layout:
 *   <OP_NAME_UPDATE or OP_NAME_FIRSTUPDATE> <push(name)> [<push(rand)>] <push(value)> OP_2DROP OP_DROP <address script...>
 *
 * NAME_FIRSTUPDATE has an extra 'rand' push between name and value. We
 * detect it by looking ahead: if the next push-data after the name is
 * short (<= 32 bytes) AND is followed by another push-data before
 * OP_2DROP, we treat it as the rand and skip to the value.
 *
 * @param {Buffer} script
 * @returns {{name:string, value:string, op:number}|null}
 */
export function parseNameScript(script: Buffer): {
    name: string;
    value: string;
    op: number;
} | null;
/**
 * Walk a verbose transaction's vouts looking for a NAME_* output whose
 * name matches `expectedName`.
 *
 * @param {any} tx
 * @param {string} expectedName
 * @returns {{name:string, value:string}|null}
 */
export function parseNameFromTx(tx: any, expectedName: string): {
    name: string;
    value: string;
} | null;
/**
 * Build Bitcoin-style push-data: opcode(s) + raw bytes.
 * @param {Buffer} data
 * @returns {Buffer}
 */
export function pushData(data: Buffer): Buffer;
/**
 * Read a push-data item from a script buffer at position `pos`.
 *
 * @param {Buffer} script
 * @param {number} pos
 * @returns {{data:Buffer, next:number}|null}
 */
export function readPushData(script: Buffer, pos: number): {
    data: Buffer;
    next: number;
} | null;
export const OP_NAME_UPDATE: 83;
export const OP_NAME_FIRSTUPDATE: 82;
export const NAME_EXPIRE_DEPTH: 36000;
