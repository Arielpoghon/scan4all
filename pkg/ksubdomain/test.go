package ksubdomain

import (
	"github.com/boy-hack/ksubdomain/core/options"
	"github.com/boy-hack/ksubdomain/runner"
	"github.com/urfave/cli/v2"
)

var testCommand = &cli.Command{
	Name:  runner.TestType,
	Usage: "Test the maximum sending speed of the local network card",
	Action: func(c *cli.Context) error {
		ether := options.GetDeviceConfig()
		runner.TestSpeed(ether)
		return nil
	},
}
