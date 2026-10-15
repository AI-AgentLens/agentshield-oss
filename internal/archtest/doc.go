// Package archtest holds architecture fitness functions. They are tests that
// turn the dependency rules in docs/architecture.md into CI failures, so a
// change that breaks a rule is caught by the gate instead of by a reviewer who
// happens to remember it.
//
// The package has no non-test code. #4315 describes the design these tests
// protect: the core engine decides, and enterprise features sit above it.
package archtest
