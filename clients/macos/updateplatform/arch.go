package updateplatform

// arch.go — what this binary is, in the manifest's vocabulary.
//
// The BINARY's architecture, not the machine's: a Rosetta-translated x86_64 build asking for arm64 would be
// handed a package it cannot install, and the refusal would arrive as a platform mismatch rather than as the
// deployment mistake it is.
const currentArch = archOfThisBuild
