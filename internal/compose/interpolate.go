package compose

import (
	"bufio"
	"bytes"
	"os"
	"path/filepath"
	"strings"
)

// lookupFunc returns the value of a variable and whether it is set.
type lookupFunc func(name string) (string, bool)

// envLookup resolves variables the way docker compose does for the common
// case: the shell environment wins, then the .env file next to the compose
// file. It's only used to *read* ports; we never write resolved values back.
func envLookup(composePath string) lookupFunc {
	dotenv := map[string]string{}
	if composePath != "" {
		if data, err := os.ReadFile(filepath.Join(filepath.Dir(composePath), ".env")); err == nil {
			dotenv = parseDotEnv(data)
		}
	}
	return func(name string) (string, bool) {
		if v, ok := os.LookupEnv(name); ok {
			return v, true
		}
		v, ok := dotenv[name]
		return v, ok
	}
}

// parseDotEnv handles KEY=VALUE lines, comments, "export " and simple quotes.
func parseDotEnv(data []byte) map[string]string {
	out := map[string]string{}
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimPrefix(line, "export ")
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		val = strings.TrimSpace(val)
		if len(val) >= 2 && (val[0] == '"' || val[0] == '\'') && val[len(val)-1] == val[0] {
			val = val[1 : len(val)-1]
		}
		out[key] = val
	}
	return out
}

func hasInterpolation(s string) bool {
	return strings.Contains(s, "$")
}

// interpolate expands $VAR, ${VAR}, ${VAR:-default}, ${VAR-default},
// ${VAR:?msg}, ${VAR?msg}, ${VAR:+alt}, ${VAR+alt} and $$. It returns false
// if a variable is needed but not set (or the syntax is something we don't
// understand), in which case the caller must not guess.
func interpolate(s string, lookup lookupFunc) (string, bool) {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '$' {
			b.WriteByte(s[i])
			continue
		}
		if i+1 >= len(s) {
			return "", false
		}
		switch next := s[i+1]; {
		case next == '$':
			b.WriteByte('$')
			i++
		case next == '{':
			end := strings.IndexByte(s[i+2:], '}')
			if end == -1 {
				return "", false
			}
			val, ok := expandBraced(s[i+2:i+2+end], lookup)
			if !ok {
				return "", false
			}
			b.WriteString(val)
			i += 2 + end
		case isNameByte(next):
			j := i + 1
			for j < len(s) && isNameByte(s[j]) {
				j++
			}
			val, ok := lookup(s[i+1 : j])
			if !ok {
				return "", false
			}
			b.WriteString(val)
			i = j - 1
		default:
			return "", false
		}
	}
	return b.String(), true
}

func expandBraced(expr string, lookup lookupFunc) (string, bool) {
	n := 0
	for n < len(expr) && isNameByte(expr[n]) {
		n++
	}
	name, rest := expr[:n], expr[n:]
	if name == "" {
		return "", false
	}
	val, set := lookup(name)
	nonEmpty := set && val != ""

	switch {
	case rest == "":
		return val, set
	case strings.HasPrefix(rest, ":-"):
		if nonEmpty {
			return val, true
		}
		return interpolate(rest[2:], lookup)
	case strings.HasPrefix(rest, "-"):
		if set {
			return val, true
		}
		return interpolate(rest[1:], lookup)
	case strings.HasPrefix(rest, ":?"):
		return val, nonEmpty
	case strings.HasPrefix(rest, "?"):
		return val, set
	case strings.HasPrefix(rest, ":+"):
		if nonEmpty {
			return interpolate(rest[2:], lookup)
		}
		return "", true
	case strings.HasPrefix(rest, "+"):
		if set {
			return interpolate(rest[1:], lookup)
		}
		return "", true
	}
	return "", false
}

func isNameByte(c byte) bool {
	return c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
}
