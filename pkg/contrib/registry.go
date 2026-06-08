// Package contrib provides an on-demand protocol loading system.
//
// Contrib modules register themselves via init() and are loaded explicitly
// with Load(name) or LoadAll(). This allows applications to import only the
// protocols they need, reducing binary size and memory footprint.
//
// Basic usage:
//
//	import _ "github.com/smallnest/goscapy/pkg/contrib/ospf"  // register
//	contrib.Load("ospf")                                       // load on demand
//
// Or load everything that's been imported:
//
//	import _ "github.com/smallnest/goscapy/pkg/contrib/ospf"
//	import _ "github.com/smallnest/goscapy/pkg/contrib/bgp"
//	contrib.LoadAll()
//
// For backward compatibility, importing github.com/smallnest/goscapy/pkg/layers
// still loads all protocols. The contrib system is opt-in for lean builds.
package contrib

import (
	"fmt"
	"sort"
	"sync"
)

// ModuleInit is the initialization function for a contrib module.
// It is called exactly once when the module is loaded, and should register
// layers, bindings, build hooks, heuristic rules, etc. via the packet
// package's registration functions.
type ModuleInit func()

type module struct {
	init   ModuleInit
	once   sync.Once
	mu     sync.Mutex
	loaded bool
}

var (
	mu      sync.RWMutex
	modules = make(map[string]*module)
)

// Register adds a contrib module by name. The init function will be called
// when Load(name) is invoked. Register is typically called from a contrib
// package's init() function.
//
// It panics if a module with the same name is registered twice.
func Register(name string, init ModuleInit) {
	mu.Lock()
	defer mu.Unlock()
	if _, exists := modules[name]; exists {
		panic(fmt.Sprintf("contrib: module %q already registered", name))
	}
	modules[name] = &module{init: init}
}

// Load loads a specific contrib module by name, calling its init function
// exactly once. Returns an error if the module is not registered.
func Load(name string) error {
	mu.RLock()
	m, ok := modules[name]
	mu.RUnlock()
	if !ok {
		return fmt.Errorf("contrib: unknown module %q", name)
	}
	m.once.Do(func() {
		m.init()
		m.mu.Lock()
		m.loaded = true
		m.mu.Unlock()
	})
	return nil
}

// LoadAll loads all registered contrib modules, calling each init function
// exactly once. Modules are loaded in alphabetical order for determinism.
func LoadAll() {
	mu.RLock()
	names := make([]string, 0, len(modules))
	for name := range modules {
		names = append(names, name)
	}
	mu.RUnlock()
	sort.Strings(names)
	for _, name := range names {
		_ = Load(name)
	}
}

// List returns the names of all registered contrib modules, sorted
// alphabetically.
func List() []string {
	mu.RLock()
	defer mu.RUnlock()
	names := make([]string, 0, len(modules))
	for name := range modules {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// IsLoaded reports whether a contrib module has been loaded.
func IsLoaded(name string) bool {
	mu.RLock()
	m, ok := modules[name]
	mu.RUnlock()
	if !ok {
		return false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.loaded
}

// Loaded returns the names of all loaded contrib modules, sorted
// alphabetically.
func Loaded() []string {
	mu.RLock()
	defer mu.RUnlock()
	var names []string
	for name, m := range modules {
		m.mu.Lock()
		l := m.loaded
		m.mu.Unlock()
		if l {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names
}
