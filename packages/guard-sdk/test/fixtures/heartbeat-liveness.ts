/**
 * Liveness fixture. Creates a Guard with a live heartbeat interval and then runs
 * off the end of the script. If the interval were not unref'd, this process
 * would never exit and the test that spawns it would time out.
 */
import { Guard } from '../../src/guard';

const guard = await Guard.create({
  licenseKey: 'lic_test',
  serverId: 'srv_liveness',
  controlPlaneUrl: process.argv[2],
  heartbeatIntervalMs: 1_000,
  onDiagnostic: () => {},
});

// Prove the guard is usable, then deliberately do NOT call close().
guard.verify({ kind: 'tools_list', tools: [{ name: 'read_file', description: 'Read a file.' }] });
process.stdout.write('started\n');
