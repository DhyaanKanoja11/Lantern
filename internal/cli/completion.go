package cli

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
)

var completionCmd = &cobra.Command{
	Use:   "completion [bash|zsh|fish|powershell]",
	Short: "Generate shell completion script",
	Long: `Generate shell completion scripts for Lantern.

To load completions in your current shell session or persist them:

Bash:
  $ source <(lantern completion bash)
  # To load completions for each session, execute once:
  # Linux:
  $ lantern completion bash > /etc/bash_completion.d/lantern
  # macOS:
  $ lantern completion bash > $(brew --prefix)/etc/bash_completion.d/lantern

Zsh:
  # If shell completion is not already enabled in your environment,
  # you will need to enable it. You can execute the following once:
  $ echo "autoload -U compinit; compinit" >> ~/.zshrc
  # To load completions for each session, execute once:
  $ lantern completion zsh > "${fpath[1]}/_lantern"
  # You will need to start a new shell for this setup to take effect.

Fish:
  $ lantern completion fish | source
  # To load completions for each session, execute once:
  $ lantern completion fish > ~/.config/fish/completions/lantern.fish

PowerShell:
  PS> lantern completion powershell | Out-String | Invoke-Expression
  # To load completions for every new session, run:
  PS> lantern completion powershell > lantern.ps1
  # and source this file from your PowerShell profile.`,
	DisableFlagsInUseLine: true,
	ValidArgs:             []string{"bash", "zsh", "fish", "powershell"},
	Args:                  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		out := cmd.OutOrStdout()
		root := cmd.Root()

		switch strings.ToLower(args[0]) {
		case "bash":
			return root.GenBashCompletion(out)
		case "zsh":
			return root.GenZshCompletion(out)
		case "fish":
			return root.GenFishCompletion(out, true)
		case "powershell":
			return root.GenPowerShellCompletionWithDesc(out)
		default:
			return fmt.Errorf("unsupported shell %q: must be one of bash, zsh, fish, powershell", args[0])
		}
	},
}
