package cli

import (
	"bytes"
	"strings"
	"testing"
)

func TestCompletionCommand(t *testing.T) {
	tests := []struct {
		shell           string
		expectedMarkers []string
	}{
		{
			shell:           "bash",
			expectedMarkers: []string{"__start_lantern", "complete -o default -F __start_lantern lantern"},
		},
		{
			shell:           "zsh",
			expectedMarkers: []string{"#compdef lantern", "compdef _lantern lantern"},
		},
		{
			shell:           "fish",
			expectedMarkers: []string{"complete -c lantern", "__lantern_perform_completion"},
		},
		{
			shell:           "powershell",
			expectedMarkers: []string{"Register-ArgumentCompleter", "'lantern'"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.shell, func(t *testing.T) {
			buf := new(bytes.Buffer)
			errBuf := new(bytes.Buffer)
			rootCmd.SetOut(buf)
			rootCmd.SetErr(errBuf)
			rootCmd.SetArgs([]string{"completion", tc.shell})
			defer func() {
				rootCmd.SetOut(nil)
				rootCmd.SetErr(nil)
				rootCmd.SetArgs(nil)
			}()

			if err := rootCmd.Execute(); err != nil {
				t.Fatalf("expected completion %s to succeed, got error: %v", tc.shell, err)
			}

			out := buf.String()
			if len(out) == 0 {
				t.Fatalf("expected non-empty completion output for %s", tc.shell)
			}

			for _, marker := range tc.expectedMarkers {
				if !strings.Contains(out, marker) {
					t.Errorf("expected %s completion output to contain %q", tc.shell, marker)
				}
			}
		})
	}
}

func TestCompletionCommand_InvalidShell(t *testing.T) {
	buf := new(bytes.Buffer)
	errBuf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(errBuf)
	rootCmd.SetArgs([]string{"completion", "tcsh"})
	defer func() {
		rootCmd.SetOut(nil)
		rootCmd.SetErr(nil)
		rootCmd.SetArgs(nil)
	}()

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("expected error for unsupported shell, got nil")
	}
	if !strings.Contains(err.Error(), "unsupported shell") {
		t.Errorf("expected unsupported shell error message, got: %v", err)
	}
}

func TestCompletionCommand_MissingArg(t *testing.T) {
	buf := new(bytes.Buffer)
	errBuf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(errBuf)
	rootCmd.SetArgs([]string{"completion"})
	defer func() {
		rootCmd.SetOut(nil)
		rootCmd.SetErr(nil)
		rootCmd.SetArgs(nil)
	}()

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("expected error when shell argument is missing, got nil")
	}
}
