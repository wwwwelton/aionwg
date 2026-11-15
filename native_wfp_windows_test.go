//go:build windows

package main

import (
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

func TestNativeWFPABISizes(t *testing.T) {
	checks := []struct {
		name string
		got  uintptr
		want uintptr
	}{
		{"FWPM_SESSION0", unsafe.Sizeof(wfpSession{}), 72},
		{"FWPM_PROVIDER0", unsafe.Sizeof(wfpProvider{}), 64},
		{"FWPM_SUBLAYER0", unsafe.Sizeof(wfpSubLayer{}), 72},
		{"FWP_VALUE0", unsafe.Sizeof(wfpValue{}), 16},
		{"FWP_CONDITION_VALUE0", unsafe.Sizeof(wfpConditionValue{}), 16},
		{"FWPM_FILTER_CONDITION0", unsafe.Sizeof(wfpFilterCondition{}), 40},
		{"FWPM_ACTION0", unsafe.Sizeof(wfpAction{}), 20},
		{"FWPM_FILTER0", unsafe.Sizeof(wfpFilter{}), 200},
		{"FWP_BYTE_BLOB", unsafe.Sizeof(wfpByteBlob{}), 16},
	}
	for _, check := range checks {
		if check.got != check.want {
			t.Errorf("%s size=%d, want %d", check.name, check.got, check.want)
		}
	}
	if got := unsafe.Offsetof(wfpFilter{}.filterID); got != 176 {
		t.Errorf("FWPM_FILTER0.filterId offset=%d, want 176", got)
	}
}

func TestNativeWFPFilterKeyIsStableAndDistinct(t *testing.T) {
	layer := windows.GUID{Data1: 1}
	first := nativeWFPFilterKey(`C:\Games\Aion2\Aion2.exe`, layer)
	second := nativeWFPFilterKey(`C:\Games\Aion2\Aion2.exe`, layer)
	otherPath := nativeWFPFilterKey(`C:\Games\Other\Aion2.exe`, layer)
	otherLayer := nativeWFPFilterKey(`C:\Games\Aion2\Aion2.exe`, windows.GUID{Data1: 2})
	if first != second {
		t.Fatal("same WFP filter input produced different keys")
	}
	if first == otherPath || first == otherLayer {
		t.Fatal("different WFP filters produced the same key")
	}
}

func TestNativeWFPErrorCode(t *testing.T) {
	if got := wfpCode(wfpAPIError{code: fwpEFilterNotFound}); got != fwpEFilterNotFound {
		t.Fatalf("wfpCode=%#x, want %#x", got, uint32(fwpEFilterNotFound))
	}
}
