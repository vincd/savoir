package utils

import (
	"fmt"
	"runtime"
)

var AppVersion AppVersionInfo

var NAME = "savoir"
var VERSION = "development version"
var REVISION = "HEAD"
var BRANCH = "HEAD"
var BUILT = "unknown"

type AppVersionInfo struct {
	Name         string `json:"name"`
	Version      string `json:"version"`
	Revision     string `json:"revision"`
	Branch       string `json:"branch"`
	GOVersion    string `json:"go_version"`
	BuiltAt      string `json:"built_at"`
	OS           string `json:"os"`
	Architecture string `json:"architecture"`
}

func (v *AppVersionInfo) ShortLine() string {
	return "Miscellaneous tools for pentest"
}

func (v *AppVersionInfo) LongLine() string {
	return "A collection of tools to exploit various vulnerabilities during pentest."
}

func (v *AppVersionInfo) Extended() string {
	version := fmt.Sprintf("Git revision: %s\n", v.Revision)
	version += fmt.Sprintf("Git branch:   %s\n", v.Branch)
	version += fmt.Sprintf("GO version:   %s\n", v.GOVersion)
	version += fmt.Sprintf("Built:        %s\n", v.BuiltAt)
	version += fmt.Sprintf("OS/Arch:      %s/%s\n", v.OS, v.Architecture)

	return version
}

func init() {
	AppVersion = AppVersionInfo{
		Name:         NAME,
		Version:      VERSION,
		Revision:     REVISION,
		Branch:       BRANCH,
		GOVersion:    runtime.Version(),
		BuiltAt:      BUILT,
		OS:           runtime.GOOS,
		Architecture: runtime.GOARCH,
	}
}
