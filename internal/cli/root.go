// Package cli wires the cobra command surface.
package cli

import (
	"fmt"
	"os"
	"runtime/debug"
	"time"

	"github.com/JosephITA/flyingfish/internal/checks"
	"github.com/JosephITA/flyingfish/internal/engine"
	"github.com/JosephITA/flyingfish/internal/kube"
	"github.com/JosephITA/flyingfish/internal/output"
	"github.com/spf13/cobra"
)

// Version is injected at build time via -ldflags; when absent (plain
// `go install module@version`), the module version from build info is used.
var Version = "dev"

func version() string {
	if Version != "dev" {
		return Version
	}
	if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" && info.Main.Version != "(devel)" {
		return info.Main.Version
	}
	return Version
}

type options struct {
	kubeconfig, kubecontext             string
	remoteKubeconfig, remoteKubecontext string
	peer                                string
	format                              string
	timeout                             time.Duration
	verbose                             bool
	noColor                             bool
}

func Execute() {
	if err := newRoot().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(3)
	}
}

func newRoot() *cobra.Command {
	root := &cobra.Command{
		Use:   "flyingfish",
		Short: "Diagnose Liqo inter-cluster connectivity problems",
		Long: `flyingfish walks the layers Liqo connectivity depends on — control plane,
gateway exposure, WireGuard tunnel, Geneve overlay, CIDR remapping, CNI
interactions and reflection — and points at the first broken link.`,
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.AddCommand(newCheck(), newVersion())
	return root
}

func newVersion() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the flyingfish version",
		Run: func(cmd *cobra.Command, _ []string) {
			fmt.Fprintln(cmd.OutOrStdout(), "flyingfish", version())
		},
	}
}

func newCheck() *cobra.Command {
	o := &options{}
	cmd := &cobra.Command{
		Use:   "check",
		Short: "Run the passive diagnostic suite against one or two clusters",
		PreRunE: func(cmd *cobra.Command, _ []string) error {
			switch o.format {
			case "text", "json":
				return nil
			default:
				return fmt.Errorf("invalid --output %q: must be text or json", o.format)
			}
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runCheck(cmd, o)
		},
	}
	f := cmd.Flags()
	f.StringVar(&o.kubeconfig, "kubeconfig", "", "path to the local cluster kubeconfig (default: $KUBECONFIG or ~/.kube/config)")
	f.StringVar(&o.kubecontext, "context", "", "kubeconfig context for the local cluster")
	f.StringVar(&o.remoteKubeconfig, "remote-kubeconfig", "", "kubeconfig of the peer cluster (enables dual-cluster cross-checks)")
	f.StringVar(&o.remoteKubecontext, "remote-context", "", "kubeconfig context for the peer cluster")
	f.StringVar(&o.peer, "peer", "", "restrict checks to one ForeignCluster name")
	f.StringVarP(&o.format, "output", "o", "text", "output format: text|json")
	f.DurationVar(&o.timeout, "timeout", 15*time.Second, "per-check timeout")
	f.BoolVarP(&o.verbose, "verbose", "v", false, "show evidence for passing checks too")
	f.BoolVar(&o.noColor, "no-color", false, "disable colored output")
	return cmd
}

func runCheck(cmd *cobra.Command, o *options) error {
	local, err := kube.Connect(o.kubeconfig, o.kubecontext, "local")
	if err != nil {
		return err
	}
	var remote *kube.Cluster
	if o.remoteKubeconfig != "" || o.remoteKubecontext != "" {
		remote, err = kube.Connect(o.remoteKubeconfig, o.remoteKubecontext, "remote")
		if err != nil {
			return err
		}
	}

	var remoteCluster engine.Cluster
	remoteName := ""
	if remote != nil {
		remoteCluster = remote
		remoteName = remote.Name
	}
	ctx := engine.NewCtx(local, remoteCluster, o.peer, o.timeout)

	if o.format == "json" {
		results := engine.Run(cmd.Context(), ctx, checks.All(), nil)
		peeringInfo := checks.PeeringInfo(cmd.Context(), ctx)
		if err := output.JSON(cmd.OutOrStdout(), results, ctx.Facts(), peeringInfo, version()); err != nil {
			return err
		}
		os.Exit(output.ExitCode(results))
	}

	color := output.ColorEnabled() && !o.noColor
	r := output.NewRenderer(cmd.OutOrStdout(), color, o.verbose)
	r.Banner(local.Name, remoteName, version())
	start := time.Now()
	results := engine.Run(cmd.Context(), ctx, checks.All(), r.Emit)
	elapsed := time.Since(start)

	for _, t := range checks.PeeringInfo(cmd.Context(), ctx) {
		r.Table(t)
	}
	r.FactSheet(ctx.Facts())
	r.Table(output.BuildResultsTable(results))
	r.Summary(results, elapsed)
	os.Exit(output.ExitCode(results))
	return nil
}
