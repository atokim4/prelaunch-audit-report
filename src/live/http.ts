import type { LiveCount } from "../types.ts";

export interface LiveHttpOptions {
  /** Requests per second, at most. */
  rate: number;
  /** Hard stop: the probe fails rather than send more than this. */
  maxRequests: number;
  timeoutMs: number;
  fetch?: typeof fetch;
}

export interface LiveResponse {
  status: number;
  headers: Headers;
  /** Parsed JSON body, or undefined. Callers read only counts and error codes from it. */
  json: unknown;
}

/**
 * The only door to the live project. Sends requests one at a time, no faster than `rate`, and
 * refuses methods that write: GET for reads, POST only for sign-in, sign-out and storage listing.
 */
export class LiveHttp {
  readonly origin: string;
  private readonly options: LiveHttpOptions;
  private last = 0;
  private queue: Promise<unknown> = Promise.resolve();
  sent = 0;

  constructor(origin: string, options: LiveHttpOptions) {
    this.origin = origin;
    this.options = options;
  }

  request(method: "GET" | "HEAD" | "POST", path: string, init: { headers: Record<string, string>; body?: unknown }) {
    if (
      method === "POST" &&
      !/^\/(auth\/v1\/(token\?grant_type=password|logout)|storage\/v1\/object\/list\/)/.test(path)
    ) {
      throw new Error(`live probe: refusing POST ${path.split("?")[0]} (read-only)`);
    }
    const run = async (): Promise<LiveResponse> => {
      if (this.sent >= this.options.maxRequests) {
        throw new Error(`live probe: stopped at --live-max-requests ${this.options.maxRequests}`);
      }
      const wait = this.last + 1000 / this.options.rate - Date.now();
      if (wait > 0) await new Promise((resolve) => setTimeout(resolve, wait));
      this.last = Date.now();
      this.sent += 1;
      let response: Response;
      try {
        response = await (this.options.fetch ?? fetch)(`${this.origin}${path}`, {
          method,
          headers: { ...init.headers, ...(init.body === undefined ? {} : { "content-type": "application/json" }) },
          body: init.body === undefined ? undefined : JSON.stringify(init.body),
          redirect: "manual",
          signal: AbortSignal.timeout(this.options.timeoutMs),
        });
      } catch (error) {
        const where = `${method} ${path.split("?")[0]}`;
        if (error instanceof Error && error.name === "TimeoutError") {
          throw new Error(`${where}: no answer in ${this.options.timeoutMs / 1000} s`, { cause: error });
        }
        throw new Error(`${where}: ${errorText(error)}`, { cause: error });
      }
      const text = await response.text();
      let json: unknown;
      try {
        json = text ? JSON.parse(text) : undefined;
      } catch {
        json = undefined;
      }
      return { status: response.status, headers: response.headers, json };
    };
    const next = this.queue.then(run, run);
    this.queue = next.catch(() => undefined);
    return next;
  }
}

const field = (json: unknown, key: string): string | undefined => {
  if (!json || typeof json !== "object") return undefined;
  const value = (json as Record<string, unknown>)[key];
  return typeof value === "string" || typeof value === "number" ? String(value) : undefined;
};

/** Total from a PostgREST `Content-Range: 0-9/42` or `*\/42` header. */
export function rangeTotal(header: string | null): number | undefined {
  const match = /\/(\d+)\s*$/.exec(header ?? "");
  return match ? Number(match[1]) : undefined;
}

/**
 * A PostgREST answer → a count. Only 42501 (permission denied) and an RLS refusal are "blocked";
 * a missing table is "missing"; everything else (401, JWT errors, 5xx, an odd body) is inconclusive.
 */
export function classify(response: LiveResponse): LiveCount {
  const code = field(response.json, "code") ?? "";
  if (response.status >= 200 && response.status < 300) {
    const n = rangeTotal(response.headers.get("content-range"));
    return n === undefined ? { status: "inconclusive", reason: "no row count in the answer" } : { status: "count", n };
  }
  const message = field(response.json, "message") ?? "";
  if (code === "42501" || /row-level security/i.test(message)) return { status: "blocked", code: code || "42501" };
  if (code === "PGRST205" || code === "42P01") return { status: "missing", code };
  const reason = [`HTTP ${response.status}`, code, message].filter(Boolean).join(" ");
  return { status: "inconclusive", reason: reason.slice(0, 160) };
}

export const errorText = (error: unknown): string => (error instanceof Error ? error.message : String(error));
