package enterprise

// FailClosed is post-eval middleware. When fail_closed=true in managed config,
// converts evaluation errors (nil Result) to BLOCK decisions instead of allowing through.
func FailClosed(cfg *ManagedConfig) EvalMiddleware {
	return func(ctx *EvalContext, next func()) {
		next()
		if cfg.FailClosed && ctx.Result == nil {
			ctx.Blocked = true
			ctx.BlockMsg = "AgentShield: policy error — blocking (fail_closed enabled)"
		}
	}
}
