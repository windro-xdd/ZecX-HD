package internal

import (
	"bufio"
	"os"
	"strconv"
	"strings"
)

type NetTotals struct { In, Out int64 }

func ReadProcTotals() (map[string]NetTotals, error) {
	f, err := os.Open("/proc/net/dev")
	if err != nil { return nil, err }
	defer f.Close()
	s := bufio.NewScanner(f)
	// Skip first two lines
	for i := 0; i < 2 && s.Scan(); i++ {}
	res := map[string]NetTotals{}
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		parts := strings.Fields(strings.ReplaceAll(line, ":", " "))
		if len(parts) < 17 { continue }
		iface := parts[0]
		inBytes, _ := strconv.ParseInt(parts[1], 10, 64)
		outBytes, _ := strconv.ParseInt(parts[9], 10, 64)
		res[iface] = NetTotals{In: inBytes, Out: outBytes}
	}
	return res, s.Err()
}

func SumTotals(m map[string]NetTotals) (int64, int64) {
	var in, out int64
	for name, t := range m {
		if strings.HasPrefix(name, "lo") { continue }
		in += t.In
		out += t.Out
	}
	return in, out
}
