// adgraph.test.mjs — the ATTACK-PATH VIEW (the AD tier's thin rung): roast/lateral
// evidence lands as graph edges (account -> SPN -> host -> reachable-via adapter)
// and the console/report can answer "shortest path from current access to a DA-class
// principal" HONESTLY — every hop is enum evidence or a RAN lateral exec, never a
// claimed route. Hermetic: a live Surface, no I/O.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Surface } from '../engine/surface.mjs';
import { queryGraph, ingestAdRoastEvidence, ingestLateralEvidence, shortestPath, pathsToPrivileged, adTraverse } from '../engine/graphquery.mjs';

function engagementGraph() {
  const s = new Surface({ engagement: 'ad-graph-' + Date.now(), signedBy: 'test', cidrs: ['10.0.0.0/8'] });
  const hostA = s.host('10.0.0.4', { label: 'agent-host' });   // current access
  s.foothold(hostA, 'agent');
  const hostB = s.host('10.0.0.9', { label: 'db.corp.local' }); // recon surfaced this
  return { s, hostA, hostB };
}

test('roast evidence lands account -> SPN -> host edges with the DA-class flag', () => {
  const { s, hostB } = engagementGraph();
  const added = ingestAdRoastEvidence(s, {
    realm: 'CORP.LOCAL',
    accounts: [
      { user: 'svc-sql', daClass: true, spns: ['MSSQLSvc/db.corp.local:1433'] },
      { user: 'bob', daClass: false, spns: ['HTTP/web.corp.local'] },
    ],
  });
  assert.equal(added.accounts, 2);
  assert.equal(added.spns, 2);
  const g = s.toJSON();
  const acc = g.nodes.find((n) => n.type === 'account' && n.label === 'svc-sql');
  assert.ok(acc && acc.daClass === true);
  const spn = g.nodes.find((n) => n.type === 'spn' && n.label === 'MSSQLSvc/db.corp.local:1433');
  assert.ok(spn);
  assert.ok(g.edges.some((e) => e.from === acc.id && e.to === spn.id && e.kind === 'has-spn'));
  assert.ok(g.edges.some((e) => e.from === spn.id && e.to === hostB && e.kind === 'runs-on'), 'the SPN host resolved to the recon-surfaced host by name');
  // re-ingestion dedups the account (no double nodes)
  ingestAdRoastEvidence(s, { realm: 'CORP.LOCAL', accounts: [{ user: 'svc-sql', daClass: true, spns: ['MSSQLSvc/db.corp.local:1433'] }] });
  assert.equal(s.toJSON().nodes.filter((n) => n.type === 'account' && n.label === 'svc-sql').length, 1);
});

test('lateral reachability lands ONLY on a ran exec (measured, never claimed)', () => {
  const { s, hostA, hostB } = engagementGraph();
  const nope = ingestLateralEvidence(s, { srcHost: '10.0.0.4', target: '10.0.0.9', adapter: 'wmi', ok: false });
  assert.equal(nope.added, false);
  assert.match(nope.reason, /measured, never claimed/);
  const yes = ingestLateralEvidence(s, { srcHost: '10.0.0.4', target: '10.0.0.9', adapter: 'psexec', ok: true });
  assert.equal(yes.added, true);
  assert.equal(yes.kind, 'reachable-via:psexec');
  assert.ok(s.toJSON().edges.some((e) => e.from === hostA && e.to === hostB && e.kind === 'reachable-via:psexec'));
});

test('the breach question: shortest measured path from the foothold to the DA-class principal', () => {
  const { s, hostA } = engagementGraph();
  ingestAdRoastEvidence(s, { realm: 'CORP.LOCAL', accounts: [{ user: 'svc-sql', daClass: true, spns: ['MSSQLSvc/db.corp.local:1433'] }] });
  ingestLateralEvidence(s, { srcHost: '10.0.0.4', target: '10.0.0.9', adapter: 'psexec', ok: true });
  const r = pathsToPrivileged(s.toJSON());
  assert.equal(r.assessed.daClassPrincipals, 1);
  assert.equal(r.paths.length, 1);
  assert.equal(r.paths[0].from, hostA);
  assert.equal(r.paths[0].principal, 'svc-sql');
  assert.equal(r.paths[0].hops, 3); // hostA -reachable-via-> hostB -(runs-on rev)-> spn -(has-spn rev)-> account
  const labels = r.paths[0].path.map((id) => s.toJSON().nodes.find((n) => n.id === id).label);
  assert.deepEqual(labels, ['agent-host', 'db.corp.local', 'MSSQLSvc/db.corp.local:1433', 'svc-sql']);
});

test('honest empty: no DA-class principals, or no measured path — said plainly', () => {
  const { s } = engagementGraph();
  const none = pathsToPrivileged(s.toJSON());
  assert.equal(none.paths.length, 0);
  assert.match(none.note, /no DA-class principals/);
  ingestAdRoastEvidence(s, { realm: 'CORP.LOCAL', accounts: [{ user: 'svc-sql', daClass: true, spns: ['MSSQLSvc/isolated.corp.local'] }] });
  const noPath = pathsToPrivileged(s.toJSON());
  assert.equal(noPath.paths.length, 0);
  assert.match(noPath.note, /no path from current access/);
});

test('the traversal policy is the honest privilege flow (movement fwd, containment rev, provenance never)', () => {
  assert.equal(adTraverse({ kind: 'reachable-via:wmi' }), 'fwd');
  assert.equal(adTraverse({ kind: 'runs-on' }), 'rev');
  assert.equal(adTraverse({ kind: 'has-spn' }), 'rev');
  assert.equal(adTraverse({ kind: 'seen-from' }), null);
  assert.equal(adTraverse({ kind: 'recon' }), null);
});

test('shortestPath: plain directed BFS utility + honest null when unreachable', () => {
  const { s, hostA, hostB } = engagementGraph();
  const g = s.toJSON();
  assert.equal(shortestPath(g, hostA, (n) => n.id === hostB), null, 'no edge yet');
  ingestLateralEvidence(s, { srcHost: '10.0.0.4', target: '10.0.0.9', adapter: 'wmi', ok: true });
  const hit = shortestPath(s.toJSON(), hostA, (n) => n.id === hostB);
  assert.equal(hit.hops, 1);
  assert.deepEqual(hit.path, [hostA, hostB]);
});

test('ingestion refuses a non-Surface and the NL query still works over the enriched graph', () => {
  const { s } = engagementGraph();
  assert.throws(() => ingestAdRoastEvidence({}, { accounts: [] }), /live Surface/);
  ingestAdRoastEvidence(s, { realm: 'CORP.LOCAL', accounts: [{ user: 'svc-sql', daClass: true, spns: ['MSSQLSvc/db.corp.local:1433'] }] });
  const q = queryGraph(s.toJSON(), 'accounts');
  assert.equal(q.count, 1);
  assert.equal(q.matched[0].label, 'svc-sql');
});
