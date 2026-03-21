package main

// Tool name families for MCP rules — sourced from existing packs.
var (
	ReadTools    = []string{"read_file", "cat_file", "get_file_contents", "open_file", "view_file"}
	WriteTools   = []string{"write_file", "create_file", "edit_file", "save_file", "update_file", "append_file", "str_replace_editor", "write_to_file"}
	DeleteTools  = []string{"delete_file", "remove_file", "unlink"}
	NetworkTools = []string{"http_request", "network_request", "fetch_url", "make_request"}

	// ReadWriteTools is the union of read + write tools.
	ReadWriteTools = append(append([]string{}, ReadTools...), WriteTools...)
	// AllFileTools includes read, write, and delete tools.
	AllFileTools = append(append([]string{}, ReadWriteTools...), DeleteTools...)
)
