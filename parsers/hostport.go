package parsers

import (
	"bufio"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/firefart/aquatone/core"
)

type HostPortParser struct{}

func NewHostPortParser() *HostPortParser {
	return &HostPortParser{}
}

func getKeysFromMap(m map[string]struct{}) []string {
	keys := make([]string, len(m))
	i := 0
	for k := range m {
		keys[i] = k
		i++
	}
	return keys
}

func (p *HostPortParser) Parse(r io.Reader) ([]string, error) {
	urlMap := make(map[string]struct{})

	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		x := scanner.Text()
		parsed, err := parseLine(x)
		if err != nil {
			return nil, err
		}
		for _, p := range parsed {
			urlMap[p] = struct{}{}
		}
	}
	return getKeysFromMap(urlMap), nil
}

func parseLine(line string) ([]string, error) {
	var urls []string
	split := strings.Split(line, ":")
	if len(split) != 2 {
		return nil, fmt.Errorf("invalid format. line does not contain exactly one : %q", line)
	}
	host := split[0]
	ports := strings.Split(split[1], ",")
	if len(ports) < 1 {
		return nil, fmt.Errorf("invalid port format for %q", split[1])
	}
	for _, p := range ports {
		portInt, err := strconv.Atoi(p)
		if err != nil {
			return nil, fmt.Errorf("invlalid format for %q: %w", p, err)
		}

		urls = append(urls, core.HostAndPortToURL(host, portInt, ""))
	}
	return urls, nil
}
