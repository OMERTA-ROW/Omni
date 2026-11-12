// Package companion implements an opt-in source prototype with explicit dock requests.
package companion

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

var Version = "0.0.0-source"
var Revision = "unreleased"

type DoctorReport struct {
	Platform           string   `json:"platform"`
	Version            string   `json:"version"`
	EvolutionConflicts []string `json:"evolution_conflicts"`
	OmniConflicts      []string `json:"omni_conflicts"`
	Network            string   `json:"network"`
	Credentials        string   `json:"credentials"`
	Changes            string   `json:"changes"`
	SignedRelease      bool     `json:"signed_release"`
}

// Look only for these two command names in explicitly configured PATH entries.
// Never execute discovered files, inspect other toolchains or read credentials.
func FindCommands(name, path, platform string) []string {
	return findCommandsWithExtensions(name, path, platform, os.Getenv("PATHEXT"))
}

func findCommandsWithExtensions(name, path, platform, pathExt string) []string {
	found := []string{}
	separator := string(os.PathListSeparator)
	if platform == "windows" {
		separator = ";"
	}
	names := []string{name}
	if platform == "windows" {
		// Include PowerShell scripts plus effective PATHEXT, even if defaults
		// have been replaced. Never interpret extensions as paths or execute them.
		for _, ext := range strings.Split(".exe;.cmd;.bat;.com;.ps1;"+pathExt, ";") {
			ext = strings.ToLower(strings.TrimSpace(ext))
			if len(ext) < 2 || ext[0] != '.' || strings.IndexFunc(ext[1:], func(r rune) bool {
				return !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9')
			}) >= 0 {
				continue
			}
			names = append(names, name+ext)
		}
	}
	seen := map[string]bool{}
	for _, dir := range strings.Split(path, separator) {
		if platform == "windows" {
			dir = strings.Trim(dir, "\"")
		}
		if dir == "" {
			continue
		} // Do not implicitly search the current directory.
		candidates := names
		if platform == "windows" {
			// Directory enumeration preserves Windows case-insensitive command
			// names when these rules are unit-tested on a Unix host too.
			candidates = nil
			entries, err := os.ReadDir(dir)
			if err != nil {
				continue
			}
			for _, entry := range entries {
				for _, wanted := range names {
					if strings.EqualFold(entry.Name(), wanted) {
						candidates = append(candidates, entry.Name())
						break
					}
				}
			}
		}
		for _, filename := range candidates {
			p := filepath.Join(dir, filename)
			info, err := os.Stat(p)
			if err != nil || !info.Mode().IsRegular() {
				continue
			}
			if platform != "windows" && info.Mode().Perm()&0111 == 0 {
				continue
			}
			if !seen[p] {
				found = append(found, p)
				seen[p] = true
			}
		}
	}
	return found
}

func Help(w io.Writer) {
	fmt.Fprintln(w, `EVOLUTION CLI — unsigned source prototype; no distributed release.
Optional companion for your existing terminal, not a replacement terminal.

Local source commands:
  evolution help             Read this reference
  evolution version          Show source version
  evolution doctor [--json]   Check platform and evolution/omni names in PATH
  evolution discover --approve [--json]
                             Opt-in local PATH-name tool discovery; nothing sent
  evolution install --dir <new-absolute-directory> --approve [--with-omni]
  evolution uninstall --dir <same-directory> --approve
  evolution project use <name> --dir <absolute-project-dir> --approve
  evolution project show --project <dir> [--json]
  evolution change new "<summary>" --project <dir> --approve [--json]
                             Records a reviewable file-level fingerprint manifest
  evolution change list --project <dir> [--json]
  evolution change diff <id> --project <dir> [--json]
                             Shows added/modified/removed files since the manifest
  evolution sandbox run <go-test|go-vet|go-build|npm-test> --project <dir> --approve [--change <id>] [--timeout 300]
                             Runs ONE fixed command locally (no shell); real log saved
                             to <dir>/.evolution/runs. Local process, not a container.
                             --change binds the run record to a reviewed manifest.
  evolution omni route "<goal>" --project <dir> [--json]
                             Shows OMNI routing for a project; no model is called
  evolution dock pair --url <https-origin> --code XXXXX-XXXXX --label "<name>"
  evolution dock status | stop | forget
  evolution dock propose --kind <kind> --project <id> --repo OWNER/REPO --instructions <text>
                             Signed OMNI Dock request; proposals are held only
  evolution release verify --dir <staged-release> [--json]
                             Checks SHA256SUMS; reports UNSIGNED unless signature files exist
  evolution release manifest --dir <staged-release> [--json]
                              Lists platform/arch, artifact path, SHA-256 check and signing status
  evolution release matrix [--json]
                              Honest per-target support: build, signing, install/update/rollback

PLANNED / BLOCKED — no account login or arbitrary tool execution:
  evolution login
  evolution connect github
  evolution nexus
  evolution agents
  evolution update --dry-run
  omni                       Direct interactive OMNI, once authorized
  evolution omni             Collision-safe fallback, once authorized

Dock requests use a dedicated local ECDSA key and signed HTTPS calls. Proposals
are held in OMNI; no commands run and no autonomy is enabled. No telemetry,
shell startup/PATH edits or other agent/tool modifications. Install/uninstall
require a new explicit directory and approval. Source builds are NOT signed
release packages. No AI model connected.`)
}

func Run(args []string, invoked string, out, errOut io.Writer) int {
	if strings.EqualFold(strings.TrimSuffix(filepath.Base(invoked), ".exe"), "omni") {
		args = append([]string{"omni"}, args...)
	}
	if len(args) == 0 {
		Help(out)
		return 0
	}
	command := args[0]
	switch command {
	case "help", "--help", "-h":
		if len(args) != 1 {
			return invalid(errOut)
		}
		Help(out)
		return 0
	case "version", "--version":
		if len(args) != 1 {
			return invalid(errOut)
		}
		fmt.Fprintf(out, "evolution %s (%s) · unsigned source · no released package\n", Version, Revision)
		return 0
	case "doctor":
		if len(args) > 2 || (len(args) == 2 && args[1] != "--json") {
			return invalid(errOut)
		}
		report := DoctorReport{runtime.GOOS + "/" + runtime.GOARCH, Version,
			FindCommands("evolution", os.Getenv("PATH"), runtime.GOOS), FindCommands("omni", os.Getenv("PATH"), runtime.GOOS),
			"NOT CONNECTED; no requests", "DISABLED; no secure-key adapter", "NONE; no configuration edited", false}
		if len(args) == 2 {
			if json.NewEncoder(out).Encode(report) != nil {
				return 1
			}
		} else {
			fmt.Fprintf(out, "LOCAL READ-ONLY CHECK · %s\nSource: %s · unsigned\nevolution name matches: %d\nomni name matches: %d\nUse evolution omni if omni is already owned by another tool.\nNo existing tools executed or modified. Auth, secure keys and releases: UNVERIFIED.\n", report.Platform, report.Version, len(report.EvolutionConflicts), len(report.OmniConflicts))
		}
		return 0
	case "discover":
		return runDiscover(args[1:], out, errOut)
	case "install", "uninstall":
		dir, approve, alias, ok := installArgs(args[1:], command == "install")
		if !ok {
			return invalid(errOut)
		}
		var err error
		if command == "install" {
			err = Install(dir, approve, alias)
		} else {
			err = Uninstall(dir, approve)
		}
		if err != nil {
			fmt.Fprintln(errOut, "Local operation blocked:", err)
			return 1
		}
		fmt.Fprintln(out, "Local source operation completed. No PATH, shell configuration, keys or other tools changed.")
		return 0
	case "project":
		return runProject(args[1:], out, errOut)
	case "change":
		return runChange(args[1:], out, errOut)
	case "sandbox":
		return runSandboxCmd(args[1:], out, errOut)
	case "release":
		return runRelease(args[1:], out, errOut)
	case "dock":
		return runDock(args[1:], out, errOut)
	case "omni":
		if len(args) > 1 && args[1] == "route" {
			return runRoute(args[2:], out, errOut)
		}
		fmt.Fprintln(errOut, "PLANNED / BLOCKED: interactive OMNI needs an authenticated model connection. Try evolution omni route \"<goal>\" --project <dir>.")
		return 2
	case "login", "connect", "nexus", "agents", "update":
		fmt.Fprintln(errOut, "PLANNED / BLOCKED: this offline source prototype has no authenticated account, model, connector, update service or runner. No request made; no keys accepted. Browser preview remains available without download.")
		return 2
	default:
		return invalid(errOut)
	}
}

func invalid(w io.Writer) int {
	fmt.Fprintln(w, "Unsupported arguments. Use evolution help. Never pass keys, tokens or passwords.")
	return 2
}
func installArgs(args []string, allowAlias bool) (dir string, approve, alias, ok bool) {
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--dir":
			if dir != "" || i+1 >= len(args) {
				return "", false, false, false
			}
			i++
			dir = args[i]
		case "--approve":
			if approve {
				return "", false, false, false
			}
			approve = true
		case "--with-omni":
			if !allowAlias || alias {
				return "", false, false, false
			}
			alias = true
		default:
			return "", false, false, false
		}
	}
	return dir, approve, alias, dir != ""
}
