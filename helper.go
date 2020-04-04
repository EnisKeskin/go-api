package main

import (
	"fmt"
	"time"
)

func date() string {
	t := time.Now()
	date := fmt.Sprintf("%d-%02d-%02d %02d:%02d:%02d",
		t.Year(), t.Month(), t.Day(),
		t.Hour(), t.Minute(), t.Second())
	return date
}

func postCount() string {
	var count string
	row, err := database.Query("SELECT COUNT(*) count FROM post")
	if err != nil {
		fmt.Print(err)
		return ""
	}
	for row.Next() {
		row.Scan(&count)
	}
	return count
}
