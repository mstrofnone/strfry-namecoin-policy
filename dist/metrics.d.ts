export class Metrics {
    constructor({ buckets }?: {
        buckets?: number[];
    });
    /** @type {Map<string, Map<string, number>>} */
    counters: Map<string, Map<string, number>>;
    /** @type {Map<string, {buckets:number[], counts:number[], sum:number, count:number}>} */
    histograms: Map<string, {
        buckets: number[];
        counts: number[];
        sum: number;
        count: number;
    }>;
    buckets: number[];
    /**
     * Increment a counter.
     * @param {string} name
     * @param {Record<string,string|number>} [labels]
     * @param {number} [delta=1]
     */
    inc(name: string, labels?: Record<string, string | number>, delta?: number): void;
    /**
     * Record an observation into a histogram.
     * @param {string} name
     * @param {number} value
     */
    observe(name: string, value: number): void;
    /**
     * Render Prometheus exposition format.
     * @returns {string}
     */
    render(): string;
    /**
     * Start an HTTP listener on 127.0.0.1:port.
     * Resolves to the http.Server. Pass port=0 to bind to a random port
     * (useful for tests). Pass null/undefined/0 to do nothing? No —
     * caller decides; here we always bind when called.
     *
     * @param {{port:number, host?:string, logger?:(level:string,...args:any[])=>void}} opts
     * @returns {Promise<http.Server>}
     */
    startServer({ port, host, logger }?: {
        port: number;
        host?: string;
        logger?: (level: string, ...args: any[]) => void;
    }): Promise<http.Server>;
}
export class NullMetrics {
    inc(): void;
    observe(): void;
    render(): string;
    startServer(): any;
}
export const DEFAULT_BUCKETS: number[];
