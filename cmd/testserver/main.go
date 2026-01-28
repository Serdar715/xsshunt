package main

import (
	"fmt"
	"net/http"
)

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.Query().Get("q")
		// Vulnerable reflection
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, "<html><body><h1>Search Results</h1><p>You searched for: %s</p></body></html>", query)
	})

	fmt.Println("Vulnerable server running on http://127.0.0.1:8081")
	http.ListenAndServe(":8081", nil)
}
