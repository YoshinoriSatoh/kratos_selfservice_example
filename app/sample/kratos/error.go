package kratos

type Error struct {
	Err error
}

func (e *Error) Error() string {
	return "kratos: " + e.Err.Error()
}
