//go:build windows

package app

import (
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

// Regression: N (DNS) followed by M (Mirror) with an active engine must not
// block Bubble Tea's Update while Windows initializes the Wintun driver.
func TestDNSThenMirrorDoesNotBlock(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	var calls atomic.Int32
	e := &Engine{
		mirror: newMirror(false, func(string, ...any) {}),
		logf:   func(string, ...any) {},
		meterOpener: func() (*meterAdapter, error) {
			calls.Add(1)
			close(started)
			<-release
			return nil, errors.New("Wintun indisponível")
		},
	}
	defer e.mirror.Close()

	e.SetNoDNS(true)
	returned := make(chan struct{})
	go func() { e.SetMirror(true); close(returned) }()
	select {
	case <-returned:
	case <-time.After(time.Second):
		close(release)
		t.Fatal("SetMirror bloqueou a interface enquanto inicializava Wintun")
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		close(release)
		t.Fatal("inicialização assíncrona não começou")
	}
	e.SetMirror(true) // repeated keypress must not start another driver init
	if got := calls.Load(); got != 1 {
		close(release)
		t.Fatalf("inicializações simultâneas: %d, esperado 1", got)
	}
	e.SetMirror(false)
	close(release)
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		e.meterMu.Lock()
		pending := e.meterOpening
		e.meterMu.Unlock()
		if !pending {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("inicialização não concluiu após liberar o driver")
}

func TestMirrorDoesNotBlockOnLogCallback(t *testing.T) {
	logEntered := make(chan struct{})
	logRelease := make(chan struct{})
	e := &Engine{
		mirror: newMirror(false, func(string, ...any) {}),
		logf:   func(string, ...any) { close(logEntered); <-logRelease },
		meterOpener: func() (*meterAdapter, error) {
			return nil, errors.New("falha simulada")
		},
	}
	defer e.mirror.Close()
	returned := make(chan struct{})
	go func() { e.SetMirror(true); close(returned) }()
	select {
	case <-returned:
	case <-time.After(time.Second):
		close(logRelease)
		t.Fatal("SetMirror bloqueou esperando o callback de log")
	}
	select {
	case <-logEntered:
	case <-time.After(time.Second):
		close(logRelease)
		t.Fatal("callback não recebeu o erro")
	}
	close(logRelease)
}

func TestLogQueueDoesNotBlockWhenFull(t *testing.T) {
	queue := make(chan logMsg, 1)
	enqueueProgramLog(queue, logMsg("primeiro"))
	returned := make(chan struct{})
	go func() {
		enqueueProgramLog(queue, logMsg("descartado"))
		close(returned)
	}()
	select {
	case <-returned:
	case <-time.After(time.Second):
		t.Fatal("fila de logs bloqueou com o consumidor ocupado")
	}
	if got := <-queue; got != logMsg("primeiro") {
		t.Fatalf("mensagem original perdida: %q", got)
	}
}
