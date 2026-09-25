// Package log defines the DNSid lifecycle-log abstractions: the signed
// events that record an agent's identity lifecycle (issuance, key rotation,
// revocation, retirement, migration, and delegation) and the interfaces used
// to write and verify that evidence.
//
// A lifecycle log is identified in an identity record by an "lr" value of the
// form {method}:{entry-ref}. This package is method-agnostic: it defines the
// shared LogEvent carrier, the Log (writer) and LogReader (verifier)
// interfaces, and a LogRegistry that maps method names to LogReader
// factories. Concrete log methods, such as the C2SP transparency-log binding
// in the c2sptlog subpackage, register themselves with a LogRegistry;
// unregistered methods resolve to a NoopLogReader that fails every evidence
// operation with a structured VerificationError.
//
// The package also models the fixed six-state agent lifecycle machine
// (AgentState) and can materialize a verified event history into the state at
// a point in time:
//
//	registry := log.NewLogRegistry()
//	// A log method binding (e.g. c2sptlog.Register) populates the registry.
//	reader, err := registry.NewReader("c2sp-tlog:public:https://tlog.example.com/dnsid#N4m8yB1Qk6RzT3w7Vp2JxA")
//	if err != nil {
//		// handle malformed lr value
//	}
//	events, err := reader.RebuildHistory(ctx, "agent.example.com")
//	if err != nil {
//		// handle verification failure
//	}
//	snapshot, err := log.NewDomainLog("agent.example.com", events).SnapshotAt(time.Now())
//
// Verification entry points on LogReader check the bilateral binding
// established by ISSUANCE (entity key and operational key signing each
// other's enrollment), operational key continuity across rotations,
// governance relationships, and non-revocation.
//
// See https://docs.dnsid.ai for protocol guides and account setup.
package log
