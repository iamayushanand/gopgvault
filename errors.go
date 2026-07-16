package main

import "errors"

var (
	ErrMissingArguments = errors.New("Operation is missing arguments")
)