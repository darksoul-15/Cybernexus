/**
 * IP blocking / containment — deliberately safe by default.
 *
 * Project rule 7: disruptive actions default to logged/simulated behind an
 * explicit "live mode" toggle, and real firewall changes must not run without
 * clear authorization. This module enforces that with TWO independent opt-ins:
 *
 *   - RESPONSE_LIVE_MODE=true      → actions are recorded as 'live' (intent)
 *   - RESPONSE_ALLOW_REAL_FIREWALL=true → actually execute an OS firewall rule
 *
 * With the second flag OFF (the default), even "live" mode NEVER shells out — it
 * logs the exact command it *would* run and reports enforced:false. Real
 * execution is intentionally gated and off in this build.
 */
import { env } from '../../config/env.js';
import type { BlockMode, BlockResult } from '@cybernexus/shared';

/** Build the platform-appropriate firewall command (not executed unless enabled). */
export function buildFirewallCommand(ip: string): string {
  if (process.platform === 'win32') {
    return `netsh advfirewall firewall add rule name="CYBERNEXUS-BLOCK ${ip}" dir=in action=block remoteip=${ip}`;
  }
  return `iptables -A INPUT -s ${ip} -j DROP`;
}

/**
 * Apply a block for an IP. Returns a BlockResult describing what happened.
 * `enforced` is true only if a real firewall command was actually executed.
 */
export async function applyBlock(ip: string): Promise<BlockResult> {
  const mode: BlockMode = env.responseLiveMode ? 'live' : 'simulated';
  const command = buildFirewallCommand(ip);

  if (mode === 'simulated') {
    console.log(`[firewall] SIMULATED block ${ip} — would run: ${command}`);
    return { ip, mode, enforced: false, message: `Simulated block (logged only). Command: ${command}` };
  }

  // mode === 'live'
  if (!env.responseAllowRealFirewall) {
    console.log(`[firewall] LIVE (dry-run) block ${ip} — real execution disabled. Would run: ${command}`);
    return {
      ip,
      mode,
      enforced: false,
      message: `Live mode recorded but real firewall execution is disabled (set RESPONSE_ALLOW_REAL_FIREWALL=true to enable). Command: ${command}`,
    };
  }

  // Real execution path — intentionally gated behind the second explicit opt-in.
  try {
    const { execFile } = await import('node:child_process');
    const { promisify } = await import('node:util');
    const run = promisify(execFile);
    if (process.platform === 'win32') {
      await run('netsh', ['advfirewall', 'firewall', 'add', 'rule', `name=CYBERNEXUS-BLOCK ${ip}`, 'dir=in', 'action=block', `remoteip=${ip}`]);
    } else {
      await run('iptables', ['-A', 'INPUT', '-s', ip, '-j', 'DROP']);
    }
    console.log(`[firewall] LIVE block ENFORCED for ${ip}`);
    return { ip, mode, enforced: true, message: `Live firewall rule applied for ${ip}` };
  } catch (e) {
    return { ip, mode, enforced: false, message: `Live block failed: ${(e as Error).message}` };
  }
}
