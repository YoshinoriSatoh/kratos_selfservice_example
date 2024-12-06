package kratos

type Provider struct {
	d Dependencies
}

type Dependencies struct {
}

type NewInput struct {
	Dependencies Dependencies
}

func New(i NewInput) (*Provider, error) {
	p := Provider{
		d: i.Dependencies,
	}
	return &p, nil
}
