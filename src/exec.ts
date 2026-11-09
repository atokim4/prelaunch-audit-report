import { execFile } from "node:child_process";

export interface ExecResult {
  code: number;
  stdout: string;
  stderr: string;
}

/** Runs a command without a shell. Resolves with the exit code instead of throwing on a non-zero exit. */
export function run(cmd: string, args: string[], opts: { cwd?: string; timeoutMs?: number } = {}): Promise<ExecResult> {
  return new Promise((resolve, reject) => {
    execFile(
      cmd,
      args,
      { cwd: opts.cwd, timeout: opts.timeoutMs ?? 120_000, maxBuffer: 64 * 1024 * 1024, encoding: "utf8" },
      (error, stdout, stderr) => {
        if (error && typeof error.code !== "number") {
          reject(new Error(`${cmd} failed to run: ${error.message}`));
          return;
        }
        resolve({ code: typeof error?.code === "number" ? error.code : 0, stdout, stderr });
      },
    );
  });
}
