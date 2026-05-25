//go:build !linux && !darwin

package route

import (
	"fmt"
)

func Table4() ([]Route, error) {
	return nil, fmt.Errorf("route: Table4 not implemented on this platform")
}

func Table6() ([]Route, error) {
	return nil, fmt.Errorf("route: Table6 not implemented on this platform")
}

func DefaultRoute4() (*Route, error) {
	return nil, fmt.Errorf("route: DefaultRoute4 not implemented on this platform")
}
