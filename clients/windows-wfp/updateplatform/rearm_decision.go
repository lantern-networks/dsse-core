package updateplatform

// serviceStartProvesRestoration is the platform-independent part of the Windows rearm verdict. A driver
// that was definitely not armed has no redirect to restore; whether the driver was readable matters too.
func serviceStartProvesRestoration(observed, preKnown, wasArmed bool) bool {
	return observed && preKnown && !wasArmed
}
