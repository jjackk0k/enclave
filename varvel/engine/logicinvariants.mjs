// VARVEL — logicinvariants: business-logic invariant EXTRACTION from API specs (T3).
//
// Pure, zero-dep, no network. Input: a parsed OpenAPI document (plus its vendor
// extensions). Output: candidate invariant probes — executable assertion recipes
// that tools/logicprobe.mjs runs against the target.
//
// The extraction claim, stated precisely:
//   - numeric bounds (minimum/maximum) and enums are read from the SCHEMA — the
//     spec is the source of the invariant;
//   - flow order comes from x-flows, state legality from x-state-machines, role
//     gating from x-role, actor separation from x-distinct-actors;
//   - x-invariant supplies what OpenAPI cannot express: a known-good CONTROL
//     request, the SETUP that reaches the interesting state, and the READBACK
//     recipe (how to observe the effect). On a real engagement these annotations
//     are operator-supplied; the derivation of the VIOLATION VALUE is always the
//     extractor's, never the annotation's.
//
// Verdicts are the prover's business (tools/logicprobe.mjs); this module only
// derives candidates. A candidate whose derived violation is not actually a
// violation per the spec (e.g. a transition FROM an allowed state) is DROPPED,
// honestly — the extractor never emits a probe it cannot motivate from the spec.

// Derive the violating value(s) for a candidate. Pure.
function deriveViolation(kind, xi, schemaProps, spec) {
  const props = schemaProps || {};
  switch (kind) {
    case 'bounds-min': {
      const min = props[xi.param] && props[xi.param].minimum;
      if (min == null) return { drop: 'no schema minimum for param ' + xi.param };
      let v = min - 1;
      const model = xi.readback && xi.readback.model;
      if (v === 0 && (model === 'subtract-param' || model === 'add-param')) v = -100; // a zero-magnitude probe cannot move state — escalate to a large negative
      return { values: [v], basis: `schema minimum ${min} → probe ${v}` };
    }
    case 'bounds-max': {
      const max = props[xi.param] && props[xi.param].maximum;
      if (max == null) return { drop: 'no schema maximum for param ' + xi.param };
      return { values: [max + 1], basis: `schema maximum ${max} → probe ${max + 1}` };
    }
    case 'server-authoritative': {
      const flagged = props[xi.param] && props[xi.param]['x-server-authoritative'];
      if (!flagged) return { drop: 'param not marked x-server-authoritative' };
      const control = xi.control && xi.control.body ? xi.control.body[xi.param] : null;
      const v = typeof control === 'number' && control > 0.02 ? 0.01 : 0.01; // near-zero tamper
      return { values: [v], basis: `x-server-authoritative param → tamper ${v} (control value ${control})` };
    }
    case 'usage-limit': {
      const enumValues = (props[xi.param] && props[xi.param].enum) || [];
      const controlVal = xi.control && xi.control.body ? xi.control.body[xi.param] : null;
      const other = enumValues.find((e) => e !== controlVal);
      if (other == null) return { drop: 'no second enum operand for the limit probe' };
      const limit = xi.limit || 1;
      return { values: [other], basis: `x-limit ${limit} + enum ${JSON.stringify(enumValues)} → second distinct operand ${JSON.stringify(other)}`, limit };
    }
    case 'flow-order': {
      const flows = spec['x-flows'] || {};
      const flow = flows[xi.flow];
      if (!flow) return { drop: 'flow ' + xi.flow + ' not declared in x-flows' };
      return { values: [null], basis: `x-flows.${xi.flow} = ${flow.join('→')} → invoke the terminal step without its predecessors`, flow };
    }
    case 'role-gate': {
      const enumValues = (props[xi.param] && props[xi.param].enum) || [];
      const terminal = enumValues[enumValues.length - 1];
      if (terminal == null) return { drop: 'no status enum to pick the attacker transition' };
      return { values: [terminal], basis: `x-role ${xi.role} + enum → low-priv session drives the machine to ${JSON.stringify(terminal)}` };
    }
    case 'state-machine': {
      const machines = spec['x-state-machines'] || {};
      const machine = machines[xi.machine];
      const t = machine && (machine.transitions || []).find((x) => x.name === xi.transition);
      if (!t) return { drop: `transition ${xi.transition} not found in x-state-machines.${xi.machine}` };
      // Where does the setup drive the entity? The last setup step's action name maps
      // to a transition whose `to` is the pre-state of the violation.
      const lastAction = xi.setup && xi.setup.length ? /\/(\w+)$/.exec(xi.setup[xi.setup.length - 1].path || '') : null;
      const preTransition = lastAction && (machine.transitions || []).find((x) => x.name === lastAction[1]);
      const preState = preTransition ? preTransition.to : null;
      if (preState && [].concat(t.from).includes(preState)) {
        return { drop: `setup leaves the entity in ${preState}, which IS an allowed from-state for ${xi.transition} — not a violation` };
      }
      return { values: [null], basis: `x-state-machines.${xi.machine}: ${xi.transition} allowed from ${JSON.stringify(t.from)}; setup reaches ${preState || 'a later state'} → invoke anyway`, toState: t.to, preState };
    }
    case 'actor-separation': {
      if (!xi.selfFrom) return { drop: 'no selfFrom recipe to obtain the caller\'s own operand' };
      return { values: ['{{self}}'], basis: 'x-distinct-actors → the caller redeems THEIR OWN operand (resolved at runtime via ' + xi.selfFrom.path + ')' };
    }
    default:
      return { drop: 'unknown invariant kind ' + kind };
  }
}

// Extract candidate invariant probes from a parsed OpenAPI document. Pure.
// Returns { candidates: [...], dropped: [{operation, reason}], specTitle }.
export function extractInvariants(spec) {
  const candidates = [];
  const dropped = [];
  const flows = (spec && spec['x-flows']) || {};
  for (const [tpl, item] of Object.entries((spec && spec.paths) || {})) {
    for (const [method, op] of Object.entries(item || {})) {
      if (!op || typeof op !== 'object' || !op['x-invariant']) continue;
      const xi = op['x-invariant'];
      const schemaProps = (((op.requestBody || {}).content || {})['application/json'] || {}).schema?.properties || {};
      const derived = deriveViolation(xi.kind, xi, schemaProps, { ...spec, 'x-flows': flows });
      if (derived.drop) { dropped.push({ operation: op.operationId || tpl, kind: xi.kind, reason: derived.drop }); continue; }
      // Build the violating request body: control body with the param replaced by the
      // derived value (kinds that carry the value in the URL/setup use violationPath).
      const v = derived.values[0];
      const controlBody = (xi.control && xi.control.body) || {};
      const violationBody = Object.keys(controlBody).length
        ? { ...controlBody, ...(xi.param && v !== null ? { [xi.param]: v } : {}) }
        : (xi.param && v !== null ? { [xi.param]: v } : {});
      candidates.push({
        id: op.operationId || `${method} ${tpl}`,
        kind: xi.kind,
        method: method.toUpperCase(),
        path: xi.concretePath || tpl,          // request path (may carry {{vars}} from setup)
        specPath: tpl,
        param: xi.param || null,
        derived,
        setup: xi.setup || [],
        controlSteps: xi.controlSteps || [],
        controlSetup: xi.controlSetup || [],
        control: xi.control || {},
        violation: { method: method.toUpperCase(), path: xi.violationPath || xi.concretePath || tpl, body: violationBody },
        readback: xi.readback || null,
        selfFrom: xi.selfFrom || null,
      });
    }
  }
  return { candidates, dropped, specTitle: (spec && spec.info && spec.info.title) || 'unknown spec' };
}

// Locate the candidate for a composed-chain step: match by kind + the observed
// CONCRETE path against the candidate's spec path template ({id} segments are wild).
export function findCandidate(candidates, { kind, path }) {
  const tplMatch = (tpl, concrete) => {
    const re = new RegExp('^' + String(tpl).replace(/[.*+?^${}()|[\]\\]/g, '\\$&').replace(/\\\{[\w-]+\\\}/g, '[\\w-]+') + '$');
    return re.test(concrete);
  };
  return candidates.find((c) => c.kind === kind && (c.path === path || tplMatch(c.specPath, path) || tplMatch(c.path, path))) || null;
}
