export function attest_process_live({ command, args }) {
  // Stub in Step-04: do not execute.
  return {
    schema_id: "MVM.PROCESS",
    version: "0.1.0",
    zone: "UNKNOWN",
    command: String(command),
    args: Array.isArray(args) ? args.map(String) : [],
  };
}