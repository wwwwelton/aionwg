package runtimefiles

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestExtractConcurrentAndVersioned(t *testing.T) {
	base := t.TempDir()
	files := []File{{Name: "driver.sys", Data: []byte("driver-one")}, {Name: "library.dll", Data: []byte("library")}}
	var wg sync.WaitGroup
	results := make(chan string, 8)
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			dir, err := extract(base, files)
			if err != nil {
				t.Error(err)
				return
			}
			results <- dir
		}()
	}
	wg.Wait()
	close(results)
	var first string
	for dir := range results {
		if first == "" {
			first = dir
		}
		if dir != first {
			t.Fatal("same payload produced different runtime paths")
		}
	}
	if first == "" {
		t.Fatal("no extraction succeeded")
	}
	data, err := os.ReadFile(filepath.Join(first, "driver.sys"))
	if err != nil || string(data) != "driver-one" {
		t.Fatalf("extracted payload: %q, %v", data, err)
	}
	next, err := extract(base, []File{{Name: "driver.sys", Data: []byte("driver-two")}})
	if err != nil || next == first {
		t.Fatalf("new payload must not overwrite loaded dependencies: %s, %v", next, err)
	}
}

func TestExtractRejectsModifiedDependency(t *testing.T) {
	base := t.TempDir()
	files := []File{{Name: "library.dll", Data: []byte("expected")}}
	dir, err := extract(base, files)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "library.dll"), []byte("modified"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := extract(base, files); err == nil {
		t.Fatal("modified DLL must not be loaded or silently replaced")
	}
}

func TestExtractRejectsPathEscape(t *testing.T) {
	for _, name := range []string{"../escape.dll", `..\escape.dll`, "C:escape.dll", ".."} {
		if _, err := extract(t.TempDir(), []File{{Name: name, Data: []byte("x")}}); err == nil {
			t.Fatalf("accepted unsafe filename %q", name)
		}
	}
}
