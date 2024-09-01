package handler

import "regexp"

func parseDate(date string) (string, string, string) {
	var (
		year  string
		month string
		day   string
	)
	r := regexp.MustCompile(`(?P<Year>\d{4})-(?P<Month>\d{2})-(?P<Day>\d{2})`)
	if r.Match([]byte(date)) {
		caps := r.FindStringSubmatch(date)
		year = caps[1]
		month = caps[2]
		day = caps[3]
	}

	return year, month, day
}
