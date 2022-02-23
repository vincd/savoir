package sekurlsa

import (
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"testing"

	"github.com/vincd/savoir/modules/minidump"
	"github.com/vincd/savoir/utils"
)

type systemInfo struct {
	MajorVersion          uint32 `json:"major_version"`
	MinorVersion          uint32 `json:"minor_version"`
	BuildNumber           uint32 `json:"build_number"`
	ProcessorArchitecture string `json:"processor_architecture"`
}

func diffStrings(str1, str2 string) []string {
	splittedStr1 := strings.Split(str1, "\n")
	splittedStr2 := strings.Split(str2, "\n")

	minLength := len(splittedStr1)
	if len(splittedStr2) < minLength {
		minLength = len(splittedStr2)
	}

	diffLines := make([]string, 0)
	for i := 0; i < minLength; i++ {
		if splittedStr1[i] != splittedStr2[i] {
			diffLines = append(diffLines, fmt.Sprintf("+ %s", splittedStr1[i]))
			diffLines = append(diffLines, fmt.Sprintf("- %s", splittedStr2[i]))
		}
	}

	for i := minLength; i < len(splittedStr1); i++ {
		diffLines = append(diffLines, fmt.Sprintf("> %s", splittedStr1[i]))
	}

	for i := minLength; i < len(splittedStr2); i++ {
		diffLines = append(diffLines, fmt.Sprintf("< %s", splittedStr2[i]))
	}

	return diffLines
}

func TestSekurlsaDumps(t *testing.T) {
	path := "../.."
	dir, err := os.Open(path)
	if err != nil {
		t.Fatalf(fmt.Sprintf("cannot open %s: %s", path, err))
		return
	}

	files, err := dir.Readdir(0)
	if err != nil {
		t.Fatalf(fmt.Sprintf("cannot read files in %s: %s", path, err))
		return
	}

	for _, file := range files {
		filename := file.Name()
		if !file.IsDir() && len(filename) > 8 && filename[len(filename)-4:] == ".DMP" {
			dumpFile := path + "/" + filename
			jsonDumpFile := dumpFile + ".json"

			r, err := minidump.NewMinidump(dumpFile)
			if err != nil {
				t.Fatalf(fmt.Sprintf("cannot read minidump %s: %s", dumpFile, err))
			}

			l, err := NewLsaSrv(r)
			if err != nil {
				t.Fatalf(fmt.Sprintf("cannot open lsass minidump %s: %s", dumpFile, err))
			}

			si := systemInfo{
				MajorVersion:          r.SystemInfo.MajorVersion,
				MinorVersion:          r.SystemInfo.MinorVersion,
				BuildNumber:           uint32(r.BuildNumber()),
				ProcessorArchitecture: r.ProcessorArchitecture().String(),
			}

			entries, err := l.ListEntries()
			if err != nil {
				t.Fatalf(fmt.Sprintf("cannot parse lsass minidump %s: %s", dumpFile, err))
			}

			o := make(map[string]interface{})
			o["system_info"] = si
			o["credentials"] = entries

			outputJson, err := utils.PrettyfyJSON(o)
			if err != nil {
				t.Fatalf(fmt.Sprintf("cannot convert entries to JSON: %s", err))
			}
			// Add new line because output files have one (lol)
			outputJson += "\n"

			jsonDumpBytes, err := ioutil.ReadFile(jsonDumpFile)
			if err != nil {
				t.Fatalf(fmt.Sprintf("cannot read JSON file %s: %s", jsonDumpFile, err))
			}
			jsonDump := string(jsonDumpBytes)

			diffLines := diffStrings(outputJson, jsonDump)
			if len(diffLines) > 0 {
				for _, line := range diffLines {
					fmt.Printf("%s\n", line)
				}

				t.Fatalf(fmt.Sprintf("LSASS minidump %s doesn't produce same output as JSON file", dumpFile))
			}
		}
	}
}
