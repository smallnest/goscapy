package contrib

import (
	"sync"
	"testing"
)

func TestRegisterAndLoad(t *testing.T) {
	// Reset global state for test isolation.
	mu.Lock()
	modules = make(map[string]*module)
	mu.Unlock()

	var called bool
	Register("test-mod", func() {
		called = true
	})

	if err := Load("test-mod"); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !called {
		t.Error("init function was not called")
	}
	if !IsLoaded("test-mod") {
		t.Error("module should be marked as loaded")
	}
}

func TestLoadIdempotent(t *testing.T) {
	mu.Lock()
	modules = make(map[string]*module)
	mu.Unlock()

	var count int
	Register("idem", func() { count++ })

	_ = Load("idem")
	_ = Load("idem")
	_ = Load("idem")

	if count != 1 {
		t.Errorf("init called %d times, want 1", count)
	}
}

func TestLoadUnknown(t *testing.T) {
	mu.Lock()
	modules = make(map[string]*module)
	mu.Unlock()

	err := Load("nonexistent")
	if err == nil {
		t.Error("expected error for unknown module")
	}
}

func TestLoadAll(t *testing.T) {
	mu.Lock()
	modules = make(map[string]*module)
	mu.Unlock()

	var a, b, c bool
	Register("charlie", func() { c = true })
	Register("alpha", func() { a = true })
	Register("bravo", func() { b = true })

	LoadAll()

	if !a || !b || !c {
		t.Errorf("not all modules loaded: a=%v b=%v c=%v", a, b, c)
	}

	loaded := Loaded()
	if len(loaded) != 3 {
		t.Errorf("Loaded() = %v, want 3 entries", loaded)
	}
	// Should be sorted.
	if loaded[0] != "alpha" || loaded[1] != "bravo" || loaded[2] != "charlie" {
		t.Errorf("Loaded() not sorted: %v", loaded)
	}
}

func TestList(t *testing.T) {
	mu.Lock()
	modules = make(map[string]*module)
	mu.Unlock()

	Register("zulu", func() {})
	Register("alpha", func() {})

	names := List()
	if len(names) != 2 {
		t.Errorf("List() = %v, want 2 entries", names)
	}
	if names[0] != "alpha" || names[1] != "zulu" {
		t.Errorf("List() not sorted: %v", names)
	}
}

func TestIsLoadedFalse(t *testing.T) {
	mu.Lock()
	modules = make(map[string]*module)
	mu.Unlock()

	Register("notyet", func() {})

	if IsLoaded("notyet") {
		t.Error("module should not be loaded yet")
	}
	if IsLoaded("nonexistent") {
		t.Error("nonexistent module should not be loaded")
	}
}

func TestLoadedBeforeLoad(t *testing.T) {
	mu.Lock()
	modules = make(map[string]*module)
	mu.Unlock()

	Register("a", func() {})
	Register("b", func() {})

	loaded := Loaded()
	if len(loaded) != 0 {
		t.Errorf("Loaded() = %v, want empty before Load()", loaded)
	}
}

func TestConcurrentLoad(t *testing.T) {
	mu.Lock()
	modules = make(map[string]*module)
	mu.Unlock()

	var count int
	var mu2 sync.Mutex
	Register("concurrent", func() {
		mu2.Lock()
		count++
		mu2.Unlock()
	})

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = Load("concurrent")
		}()
	}
	wg.Wait()

	if count != 1 {
		t.Errorf("init called %d times, want 1", count)
	}
}

func TestDoubleRegisterPanics(t *testing.T) {
	mu.Lock()
	modules = make(map[string]*module)
	mu.Unlock()

	Register("dup", func() {})
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic on double register")
		}
	}()
	Register("dup", func() {})
}
