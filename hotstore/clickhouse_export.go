package hotstore

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
)

// The count is computed before LIMIT in the same query snapshot as the rows.
// Export jobs use it to distinguish a capped file from a complete export.
func parseClickHouseExportRows(body []byte) ([]map[string]any, int, error) {
	rows := []map[string]any{}
	total := 0
	scanner := bufio.NewScanner(bytes.NewReader(body))
	scanner.Buffer(make([]byte, 0, 1024*1024), 16*1024*1024)
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		var wrapped struct {
			Raw   string      `json:"raw"`
			Total json.Number `json:"total_matches"`
		}
		if err := json.Unmarshal(line, &wrapped); err != nil {
			return nil, 0, fmt.Errorf("decode clickhouse export row: %w", err)
		}
		count, err := strconv.Atoi(wrapped.Total.String())
		if err != nil || count <= 0 || (len(rows) > 0 && count != total) {
			return nil, 0, fmt.Errorf("invalid ClickHouse export count")
		}
		total = count
		var row map[string]any
		if err := json.Unmarshal([]byte(wrapped.Raw), &row); err != nil {
			return nil, 0, fmt.Errorf("decode raw payload: %w", err)
		}
		rows = append(rows, row)
	}
	if err := scanner.Err(); err != nil {
		return nil, 0, err
	}
	if total < len(rows) {
		return nil, 0, fmt.Errorf("invalid ClickHouse export count")
	}
	return rows, total, nil
}
