package main

// companions.go — the executables this agent expects to find beside itself, declared once.
//
// Deliberately NOT behind //go:build windows even though every companion is a Windows binary: the packaging
// gate in companions_test.go has to run on the Linux CI runner, which is the only place it runs at all. A
// guard that only fires on a developer's Windows machine is not a guard. The table is plain data with no
// imports, so it costs nothing to build everywhere; the code that USES it stays Windows-tagged.
//
// Why this file exists: the branded step-up window (dsse-stepup-window.exe) was implemented, wired into the
// step-up path, and never added to the installer. Because the lookup falls back to the default browser when
// the file is absent, the ceremony kept working and nobody noticed — the feature had never actually run on an
// installed agent. A silent fallback is the right RUNTIME behaviour and the wrong DEPLOYMENT signal.
//
// Two mechanisms follow from that, and both key off this one table:
//
//  1. companions_test.go asserts every entry is installed by packaging/DsseAgent.wxs, so adding a companion
//     to the code without packaging it fails the build instead of degrading in the field.
//  2. reportCompanions() logs what is present and what is missing at startup, so a deployment gap shows up
//     immediately rather than at the moment a user needs the feature.

// companion is an executable the agent resolves next to its own binary at runtime.
type companion struct {
	// Exe is the file name as installed, and must match the Source= in packaging/DsseAgent.wxs.
	Exe string
	// Purpose is what it does, for the startup line.
	Purpose string
	// IfMissing states what the agent does without it — the consequence, not just the fact.
	IfMissing string
}

// runtimeCompanions is the single source of truth. Add an entry here when the agent starts resolving a new
// sibling executable; the packaging test will then require it to be installed.
var runtimeCompanions = []companion{
	{
		Exe:       "dsse-stepup-window.exe",
		Purpose:   "branded out-of-band step-up window (hosts the real IdP page in WebView2)",
		IfMissing: "the step-up ceremony opens the user's default browser instead",
	},
}
