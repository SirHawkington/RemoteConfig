//go:build noselfupdate

package agent

import "remoteconfig/internal/proto"

// Built with -tags noselfupdate: the agent never replaces its own executable. App releases
// still work; to change the agent, install a new build yourself.

func (a *Agent) installAgent(c proto.Command, file, id, version string) proto.CommandResult {
	return proto.CommandResult{OK: false, Output: "this agent was built without self-update; install the new build yourself"}
}

func (a *Agent) exitIfUpdating() {}

// CheckPendingUpdate has nothing to settle without self-update.
func CheckPendingUpdate(stateDir string, logf func(string, ...any)) bool { return false }

func (a *Agent) confirmUpdate() {}
