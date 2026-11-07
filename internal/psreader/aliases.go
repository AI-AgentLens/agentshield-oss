package psreader

import "strings"

//go:generate go test -run TestAliasTableInSync -update-aliases .

// canonical returns a command's canonical name and the other names it can
// resolve to.
//
// The alias table (aliases_table.go) is generated from the built-in aliases
// of a clean Windows PowerShell 5.1 session and a clean PowerShell 7 session
// (testdata/aliases/*.tsv). The reader cannot know which version runs the
// text, and stricter wins, so an alias the two versions disagree on yields
// both readings: Name is the alias's definition, and Alternatives holds the
// name as written, which is what the other version looks up as a function,
// cmdlet or native program. `curl` is Invoke-WebRequest in 5.1 and curl.exe in
// 7, so it reads as `invoke-webrequest` with the alternative `curl`; `gerr` is
// Get-Error only in 7, so it reads as `get-error` with the alternative
// `gerr`. Where both versions define an alias differently, Name is the 7.x
// definition and the 5.1 definition is the alternative.
//
// A module-qualified name (`Microsoft.PowerShell.Utility\Invoke-Expression`)
// reads as the command after the module, with the whole name, which could
// also be a relative path, as an alternative.
//
// Not covered: PowerShell 7 on macOS and Linux, which does not define the
// aliases that shadow Unix commands (`ls`, `rm`, `cat`, `cp` …). The
// tables are the Windows sessions only; a non-Windows row that routes to
// this lane would need a third table.
func canonical(written string) (string, []string) {
	lw := asciiLower(written)
	if def, ok := aliasTable[lw]; ok {
		v51, v7 := asciiLower(def[0]), asciiLower(def[1])
		switch {
		case v51 == v7:
			return v7, nil
		case v51 == "":
			return v7, []string{lw}
		case v7 == "":
			return v51, []string{lw}
		default:
			return v7, []string{v51}
		}
	}
	if module, cmd, ok := moduleQualified(written); ok && module != "" {
		name, alts := canonical(cmd)
		return name, appendUnique(alts, lw)
	}
	return lw, nil
}

// moduleQualified splits `Module\Command`. The module part must look like a
// module name, so `.\x.ps1`, `C:\x` and `dir\sub\x` are not split.
func moduleQualified(s string) (module, cmd string, ok bool) {
	i := strings.LastIndexByte(s, '\\')
	if i <= 0 || i == len(s)-1 {
		return "", "", false
	}
	module, cmd = s[:i], s[i+1:]
	if strings.ContainsAny(cmd, "/:") {
		return "", "", false
	}
	for j := 0; j < len(module); j++ {
		c := module[j]
		letter := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '_'
		if j == 0 && !letter {
			return "", "", false
		}
		if !letter && !(c >= '0' && c <= '9') && c != '.' && c != '-' {
			return "", "", false
		}
	}
	return module, cmd, true
}

func appendUnique(list []string, s string) []string {
	for _, x := range list {
		if x == s {
			return list
		}
	}
	return append(list, s)
}

// asciiLower lowers ASCII letters only. Unicode case folding maps a few
// non-ASCII letters onto ASCII ones (U+212A KELVIN SIGN to k) where
// PowerShell's ordinal comparison does not, so a full fold would read names
// PowerShell never resolves (#3771 is the same trap on the shell side).
func asciiLower(s string) string {
	for i := 0; i < len(s); i++ {
		if c := s[i]; c >= 'A' && c <= 'Z' {
			b := []byte(s)
			for j := i; j < len(b); j++ {
				if b[j] >= 'A' && b[j] <= 'Z' {
					b[j] += 'a' - 'A'
				}
			}
			return string(b)
		}
	}
	return s
}
