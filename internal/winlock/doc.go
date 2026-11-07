// Package winlock is the Windows lock behind Shield's cross-process file
// locks: the audit log chain lock, the audit upload queue and the MCP tool
// registry. On unix those take flock(2). Windows has no advisory lock, so
// this package builds one from LockFileEx (#4717).
package winlock
