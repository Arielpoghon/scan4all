package strsim

type option struct {
	ignore int  //
	ascii  bool // Select whether the algorithm uses ASCII or UTF-8.
	cmp    func(s1, s2 string) float64
	base64 bool // Select whether to use the base64 algorithm.
}

// fillOption applies the Option values to the option.
func (o *option) fillOption(opts ...Option) {
	for _, opt := range opts {
		opt.Apply(o)
	}

	opt := Default()
	opt.Apply(o)
}

type Option interface {
	Apply(*option)
}

type OptionFunc func(*option)

func (o OptionFunc) Apply(opt *option) {
	o(opt)
}

// IgnoreCase ignores letter case.
func IgnoreCase() OptionFunc {
	return OptionFunc(func(o *option) {
		o.ignore |= ignoreCase
	})
}

// IgnoreSpace ignores whitespace characters.
func IgnoreSpace() OptionFunc {
	return OptionFunc(func(o *option) {
		o.ignore |= ignoreSpace
	})
}

// UseASCII selects ASCII encoding.
func UseASCII() OptionFunc {
	return OptionFunc(func(o *option) {
		o.ascii = true
	})
}

// UseBase64 selects base64 encoding.
func UseBase64() OptionFunc {
	return OptionFunc(func(o *option) {
		o.base64 = true
	})
}
