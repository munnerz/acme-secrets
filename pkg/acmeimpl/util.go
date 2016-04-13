package acmeimpl

import (
	"errors"
	"fmt"

	"github.com/hashicorp/go-multierror"
)

func mapErrsToErr(errm map[string]error) error {
	if len(errm) == 0 {
		return nil
	}

	errs := make([]error, len(errm))
	i := 0
	for k, v := range errm {
		errs[i] = fmt.Errorf("%s: %s", k, v.Error())
		i++
	}
	return errors.New(multierror.ListFormatFunc(errs))
}
