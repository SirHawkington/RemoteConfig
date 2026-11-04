//go:build noscripts

package agent

import (
	"context"

	"remoteconfig/internal/proto"
)

// Built with -tags noscripts: the agent has no code to run scripts at all.
func (a *Agent) runScript(ctx context.Context, c proto.Command) proto.CommandResult {
	return proto.CommandResult{OK: false, Output: "this agent was built without script support"}
}
