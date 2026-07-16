// Package output renders check results as a colored terminal report or JSON.
package output

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/JosephITA/flyingfish/internal/engine"
)

const banner = `
    ___ _       _             ___ _     _
   / __\ |_   _(_)_ __   __ _/ __(_)___| |__
  / _\ | | | | | | '_ \ / _` + "`" + ` / _\ | / __| '_ \
 / /   | | |_| | | | | | (_| / /  | \__ \ | | |
 \/    |_|\__, |_|_| |_|\__, \/   |_|___/_| |_|
          |___/         |___/
`

type ansi struct{ dim, red, yellow, green, cyan, bold, reset string }

func palette(color bool) ansi {
	if !color {
		return ansi{}
	}
	return ansi{
		dim: "\033[2m", red: "\033[31m", yellow: "\033[33m",
		green: "\033[32m", cyan: "\033[36m", bold: "\033[1m", reset: "\033[0m",
	}
}

// ColorEnabled decides whether to emit ANSI colors.
func ColorEnabled() bool {
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	st, err := os.Stdout.Stat()
	return err == nil && st.Mode()&os.ModeCharDevice != 0
}

var layerTitles = map[string]string{
	"env": "ENVIRONMENT", "api": "CONTROL PLANE", "gateway": "GATEWAY EXPOSURE",
	"tunnel": "TUNNEL", "fabric": "INTRA-CLUSTER FABRIC", "ipam": "IPAM / REMAPPING",
	"cni": "CNI INTERACTIONS", "reflection": "REFLECTION",
}

type Renderer struct {
	W         io.Writer
	Color     bool
	Verbose   bool
	lastLayer string
	p         ansi
}

func NewRenderer(w io.Writer, color, verbose bool) *Renderer {
	return &Renderer{W: w, Color: color, Verbose: verbose, p: palette(color)}
}

func (r *Renderer) Banner(local, remote, version string) {
	fmt.Fprintf(r.W, "%s%s%s%s\n", r.p.cyan, banner, r.p.reset, "")
	mode := "single-cluster (add --remote-kubeconfig for cross-checks)"
	if remote != "" {
		mode = "dual-cluster"
	}
	fmt.Fprintf(r.W, " %sliqo connectivity diagnostics%s ⋅ %s\n", r.p.bold, r.p.reset, version)
	fmt.Fprintf(r.W, " %scluster:%s %s", r.p.dim, r.p.reset, local)
	if remote != "" {
		fmt.Fprintf(r.W, "  %s⇄%s  %s", r.p.cyan, r.p.reset, remote)
	}
	fmt.Fprintf(r.W, "\n %smode:%s %s\n", r.p.dim, r.p.reset, mode)
}

// Emit prints one result as it completes (live output).
func (r *Renderer) Emit(res engine.Result) {
	if res.Layer != r.lastLayer {
		fmt.Fprintf(r.W, "\n %s%s%s\n", r.p.bold, layerTitles[res.Layer], r.p.reset)
		r.lastLayer = res.Layer
	}
	icon, color := r.icon(res.Status)
	fmt.Fprintf(r.W, "  %s%s%s %s%-8s%s %s\n", color, icon, r.p.reset, r.p.dim, res.ID, r.p.reset, res.Name)
	if res.Status == engine.Pass && !r.Verbose {
		return
	}
	if res.Detail != "" {
		fmt.Fprintf(r.W, "      %s%s%s\n", color, wrapIndent(res.Detail, 6), r.p.reset)
	}
	for _, ev := range res.Evidence {
		fmt.Fprintf(r.W, "      %s· %s%s\n", r.p.dim, wrapIndent(ev, 8), r.p.reset)
	}
	if res.Remediation != "" && res.Status != engine.Pass && res.Status != engine.Skip {
		fmt.Fprintf(r.W, "      %s⚑ %s%s\n", r.p.cyan, wrapIndent(res.Remediation, 8), r.p.reset)
	}
}

// Summary prints counters and the primary diagnosis.
func (r *Renderer) Summary(results []engine.Result) {
	var pass, warnN, failN, skipN int
	for _, res := range results {
		switch res.Status {
		case engine.Pass:
			pass++
		case engine.Warn:
			warnN++
		case engine.Fail:
			failN++
		case engine.Skip:
			skipN++
		}
	}
	fmt.Fprintf(r.W, "\n %s────────────────────────────────────────%s\n", r.p.dim, r.p.reset)
	fmt.Fprintf(r.W, " %s%d passed%s ⋅ %s%d warnings%s ⋅ %s%d failed%s ⋅ %s%d skipped%s\n",
		r.p.green, pass, r.p.reset, r.p.yellow, warnN, r.p.reset, r.p.red, failN, r.p.reset, r.p.dim, skipN, r.p.reset)

	if d := engine.Diagnosis(results); d != nil {
		icon, color := r.icon(d.Status)
		fmt.Fprintf(r.W, "\n %sdiagnosis%s %s%s %s [%s]: %s%s\n",
			r.p.bold, r.p.reset, color, icon, d.ID, layerTitles[d.Layer], d.Detail, r.p.reset)
		if d.Remediation != "" {
			fmt.Fprintf(r.W, "           %s⚑ %s%s\n", r.p.cyan, wrapIndent(d.Remediation, 13), r.p.reset)
		}
	} else {
		fmt.Fprintf(r.W, "\n %sdiagnosis%s %s✓ no connectivity problems detected by passive checks%s\n",
			r.p.bold, r.p.reset, r.p.green, r.p.reset)
	}
	fmt.Fprintln(r.W)
}

func (r *Renderer) icon(s engine.Status) (string, string) {
	switch s {
	case engine.Pass:
		return "✓", r.p.green
	case engine.Warn:
		return "!", r.p.yellow
	case engine.Fail:
		return "✗", r.p.red
	default:
		return "–", r.p.dim
	}
}

// wrapIndent soft-wraps long lines so evidence stays readable in a terminal.
func wrapIndent(s string, indent int) string {
	const width = 100
	if len(s) <= width {
		return s
	}
	pad := "\n" + strings.Repeat(" ", indent)
	var b strings.Builder
	line := 0
	for _, word := range strings.Fields(s) {
		if line+len(word)+1 > width && line > 0 {
			b.WriteString(pad)
			line = 0
		} else if line > 0 {
			b.WriteString(" ")
			line++
		}
		b.WriteString(word)
		line += len(word)
	}
	return b.String()
}

// JSON emits the machine-readable contract (spec §6).
func JSON(w io.Writer, results []engine.Result, version string) error {
	type summary struct {
		Pass, Warn, Fail, Skip int
	}
	var s summary
	for _, r := range results {
		switch r.Status {
		case engine.Pass:
			s.Pass++
		case engine.Warn:
			s.Warn++
		case engine.Fail:
			s.Fail++
		case engine.Skip:
			s.Skip++
		}
	}
	payload := map[string]any{
		"version":   version,
		"results":   results,
		"summary":   s,
		"diagnosis": engine.Diagnosis(results),
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(payload)
}

// ExitCode maps results to the CLI contract: 0 pass, 1 warn, 2 fail.
func ExitCode(results []engine.Result) int {
	code := 0
	for _, r := range results {
		if r.Status == engine.Warn && code < 1 {
			code = 1
		}
		if r.Status == engine.Fail {
			return 2
		}
	}
	return code
}
