package engine

// Table is a screenshot/copy-paste friendly grid: a titled block of rows
// with column headers, rendered as a markdown table so it pastes cleanly
// into GitHub, Slack, or any chat with a developer.
type Table struct {
	Title   string     `json:"title,omitempty"`
	Headers []string   `json:"headers"`
	Rows    [][]string `json:"rows"`
}
