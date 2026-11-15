//go:build windows

package app

import (
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	rpcCAuthnWinnt       = 10
	fwpmSessionFlagDyn   = 0x00000001
	fwpEmpty             = 0
	fwpByteBlobType      = 12
	fwpMatchEqual        = 0
	fwpActionBlock       = 0x00001001
	fwpEFilterNotFound   = 0x80320003
	fwpEProviderNotFound = 0x80320005
	fwpESubLayerNotFound = 0x80320007
	fwpEAlreadyExists    = 0x80320009
)

var (
	fwpmDLL = windows.NewLazySystemDLL("fwpuclnt.dll")

	fwpmEngineOpen        = fwpmDLL.NewProc("FwpmEngineOpen0")
	fwpmEngineClose       = fwpmDLL.NewProc("FwpmEngineClose0")
	fwpmProviderAdd       = fwpmDLL.NewProc("FwpmProviderAdd0")
	fwpmProviderDelete    = fwpmDLL.NewProc("FwpmProviderDeleteByKey0")
	fwpmSubLayerAdd       = fwpmDLL.NewProc("FwpmSubLayerAdd0")
	fwpmSubLayerDelete    = fwpmDLL.NewProc("FwpmSubLayerDeleteByKey0")
	fwpmFilterAdd         = fwpmDLL.NewProc("FwpmFilterAdd0")
	fwpmFilterDelete      = fwpmDLL.NewProc("FwpmFilterDeleteByKey0")
	fwpmFilterGetByKey    = fwpmDLL.NewProc("FwpmFilterGetByKey0")
	fwpmFilterCreateEnum  = fwpmDLL.NewProc("FwpmFilterCreateEnumHandle0")
	fwpmFilterDestroyEnum = fwpmDLL.NewProc("FwpmFilterDestroyEnumHandle0")
	fwpmFilterEnum        = fwpmDLL.NewProc("FwpmFilterEnum0")
	fwpmTransactionBegin  = fwpmDLL.NewProc("FwpmTransactionBegin0")
	fwpmTransactionCommit = fwpmDLL.NewProc("FwpmTransactionCommit0")
	fwpmTransactionAbort  = fwpmDLL.NewProc("FwpmTransactionAbort0")
	fwpmGetAppID          = fwpmDLL.NewProc("FwpmGetAppIdFromFileName0")
	fwpmFreeMemory        = fwpmDLL.NewProc("FwpmFreeMemory0")
)

type wfpDisplayData struct {
	name        uintptr
	description uintptr
}

type wfpSession struct {
	sessionKey         windows.GUID
	displayData        wfpDisplayData
	flags              uint32
	txnWaitTimeoutInMS uint32
	processID          uint32
	sid                uintptr
	username           uintptr
	kernelMode         int32
}

type wfpByteBlob struct {
	size uint32
	data uintptr
}

type wfpProvider struct {
	providerKey  windows.GUID
	displayData  wfpDisplayData
	flags        uint32
	providerData wfpByteBlob
	serviceName  uintptr
}

type wfpSubLayer struct {
	subLayerKey  windows.GUID
	displayData  wfpDisplayData
	flags        uint16
	providerKey  uintptr
	providerData wfpByteBlob
	weight       uint16
}

type wfpValue struct {
	typeCode uint32
	value    uintptr
}

type wfpConditionValue struct {
	typeCode uint32
	value    uintptr
}

type wfpFilterCondition struct {
	fieldKey       windows.GUID
	matchType      uint32
	conditionValue wfpConditionValue
}

type wfpAction struct {
	typeCode   uint32
	filterType windows.GUID
}

type wfpFilter struct {
	filterKey           windows.GUID
	displayData         wfpDisplayData
	flags               uint32
	providerKey         uintptr
	providerData        wfpByteBlob
	layerKey            windows.GUID
	subLayerKey         windows.GUID
	weight              wfpValue
	numFilterConditions uint32
	filterCondition     uintptr
	action              wfpAction
	padding             uint32
	rawContext          [16]byte // UINT64 rawContext or GUID providerContextKey
	reserved            uintptr
	filterID            uint64
	effectiveWeight     wfpValue
}

var (
	nativeWFPProviderKey = windows.GUID{
		Data1: 0x0e8c1b4a, Data2: 0x7b72, Data3: 0x4e7d,
		Data4: [8]byte{0x9f, 0x1d, 0x6b, 0x38, 0x13, 0x4f, 0x22, 0x70},
	}
	nativeWFPSubLayerKey = windows.GUID{
		Data1: 0x9a0b5d1c, Data2: 0x2f4f, Data3: 0x4a8e,
		Data4: [8]byte{0x86, 0x2f, 0x18, 0x56, 0x0e, 0x99, 0x41, 0x2a},
	}

	wfpLayerALEAuthConnectV4 = windows.GUID{
		Data1: 0xc38d57d1, Data2: 0x05a7, Data3: 0x4c33,
		Data4: [8]byte{0x90, 0x4f, 0x7f, 0xbc, 0xee, 0xe6, 0x0e, 0x82},
	}
	wfpLayerALEAuthConnectV6 = windows.GUID{
		Data1: 0x4a72393b, Data2: 0x319f, Data3: 0x44bc,
		Data4: [8]byte{0x84, 0xc3, 0xba, 0x54, 0xdc, 0xb3, 0xb6, 0xb4},
	}
	wfpLayerALEAuthRecvAcceptV4 = windows.GUID{
		Data1: 0xe1cd9fe7, Data2: 0xf4b5, Data3: 0x4273,
		Data4: [8]byte{0x96, 0xc0, 0x59, 0x26, 0x95, 0xc5, 0xf7, 0xb8},
	}
	wfpLayerALEAuthRecvAcceptV6 = windows.GUID{
		Data1: 0xa3b42c97, Data2: 0x9f04, Data3: 0x4672,
		Data4: [8]byte{0xb8, 0x7e, 0xce, 0xe9, 0xc4, 0x83, 0x25, 0x7f},
	}
	wfpConditionALEAppID = windows.GUID{
		Data1: 0xd78e1e87, Data2: 0x8644, Data3: 0x4ea5,
		Data4: [8]byte{0x94, 0x37, 0xd8, 0x09, 0xec, 0xef, 0xc9, 0x71},
	}
)

type nativeWFPFilter struct {
	rule ProcessRule
	path string
}

type nativeWFPManager struct {
	mu      sync.Mutex
	engine  uintptr
	filters map[windows.GUID]nativeWFPFilter
	rules   []ProcessRule
	status  NativeWFPStatus
	logf    func(string, ...any)
}

func newNativeWFPManager(logf func(string, ...any)) *nativeWFPManager {
	return &nativeWFPManager{
		filters: make(map[windows.GUID]nativeWFPFilter),
		logf:    logf,
	}
}

func (m *nativeWFPManager) Open() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.engine != 0 {
		return nil
	}

	name := utf16Ptr("AionWG Native WFP Policy")
	session := wfpSession{
		displayData: wfpDisplayData{name: uintptr(unsafe.Pointer(&name[0]))},
		flags:       fwpmSessionFlagDyn,
	}
	var engine uintptr
	if err := wfpCall(fwpmEngineOpen, "FwpmEngineOpen0", 0, rpcCAuthnWinnt, 0,
		uintptr(unsafe.Pointer(&session)), uintptr(unsafe.Pointer(&engine))); err != nil {
		m.setErrorLocked(err)
		runtime.KeepAlive(name)
		return err
	}
	runtime.KeepAlive(name)
	m.engine = engine
	m.status = NativeWFPStatus{SessionOpen: true}
	if err := m.installObjectsLocked(); err != nil {
		m.closeLocked()
		m.setErrorLocked(err)
		return err
	}
	return nil
}

func (m *nativeWFPManager) installObjectsLocked() error {
	if err := wfpCall(fwpmTransactionBegin, "FwpmTransactionBegin0", m.engine, 0); err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			_, _, _ = fwpmTransactionAbort.Call(m.engine)
		}
	}()

	providerName := utf16Ptr("AionWG")
	provider := wfpProvider{
		providerKey: nativeWFPProviderKey,
		displayData: wfpDisplayData{name: uintptr(unsafe.Pointer(&providerName[0]))},
	}
	if err := wfpCall(fwpmProviderAdd, "FwpmProviderAdd0", m.engine,
		uintptr(unsafe.Pointer(&provider)), 0); err != nil {
		runtime.KeepAlive(providerName)
		if wfpCode(err) == fwpEAlreadyExists {
			return fmt.Errorf("provider AionWG já existe; remova a instalação antiga antes de continuar: %w", err)
		}
		return err
	}
	runtime.KeepAlive(providerName)

	subLayerName := utf16Ptr("AionWG Process Policy")
	subLayer := wfpSubLayer{
		subLayerKey: nativeWFPSubLayerKey,
		displayData: wfpDisplayData{name: uintptr(unsafe.Pointer(&subLayerName[0]))},
		providerKey: uintptr(unsafe.Pointer(&nativeWFPProviderKey)),
		weight:      0x100,
	}
	if err := wfpCall(fwpmSubLayerAdd, "FwpmSubLayerAdd0", m.engine,
		uintptr(unsafe.Pointer(&subLayer)), 0); err != nil {
		runtime.KeepAlive(subLayerName)
		return err
	}
	runtime.KeepAlive(subLayerName)
	if err := wfpCall(fwpmTransactionCommit, "FwpmTransactionCommit0", m.engine); err != nil {
		return err
	}
	committed = true
	m.status.ProviderRegistered = true
	m.status.SubLayerRegistered = true
	return nil
}

func (m *nativeWFPManager) Close() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closeLocked()
}

func (m *nativeWFPManager) closeLocked() {
	if m.engine != 0 {
		if err := m.removeObjectsLocked(); err != nil {
			m.setErrorLocked(err)
		}
		if code, _, _ := fwpmEngineClose.Call(m.engine); code != 0 {
			m.setErrorLocked(wfpAPIError{name: "FwpmEngineClose0", code: uint32(code)})
		}
	}
	m.engine = 0
	m.filters = make(map[windows.GUID]nativeWFPFilter)
	m.rules = nil
	m.status.SessionOpen = false
	m.status.ProviderRegistered = false
	m.status.SubLayerRegistered = false
	m.status.FiltersInstalled = 0
	m.status.RulesActive = 0
}

func (m *nativeWFPManager) removeObjectsLocked() error {
	if err := wfpCall(fwpmTransactionBegin, "FwpmTransactionBegin0", m.engine, 0); err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			_, _, _ = fwpmTransactionAbort.Call(m.engine)
		}
	}()
	for key := range m.filters {
		if err := wfpCall(fwpmFilterDelete, "FwpmFilterDeleteByKey0", m.engine,
			uintptr(unsafe.Pointer(&key))); err != nil && wfpCode(err) != fwpEFilterNotFound {
			return err
		}
	}
	if err := wfpCall(fwpmSubLayerDelete, "FwpmSubLayerDeleteByKey0", m.engine,
		uintptr(unsafe.Pointer(&nativeWFPSubLayerKey))); err != nil && wfpCode(err) != fwpESubLayerNotFound {
		return err
	}
	if err := wfpCall(fwpmProviderDelete, "FwpmProviderDeleteByKey0", m.engine,
		uintptr(unsafe.Pointer(&nativeWFPProviderKey))); err != nil && wfpCode(err) != fwpEProviderNotFound {
		return err
	}
	if err := wfpCall(fwpmTransactionCommit, "FwpmTransactionCommit0", m.engine); err != nil {
		return err
	}
	committed = true
	return nil
}

func (m *nativeWFPManager) ReplaceRules(rules []ProcessRule) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.engine == 0 {
		return m.rememberErrorLocked(fmt.Errorf("sessão WFP não está aberta"))
	}

	resolved := make([]ProcessRule, 0, len(rules))
	seen := make(map[string]struct{})
	for _, rule := range rules {
		if ProcessPolicy(strings.ToUpper(strings.TrimSpace(string(rule.Policy)))) != PolicyBlock {
			continue
		}
		path, err := resolveNativeWFPPath(rule)
		if err != nil {
			return m.rememberErrorLocked(fmt.Errorf("regra BLOCK %q: %w", rule.Name, err))
		}
		normalized := strings.ToLower(filepath.Clean(path))
		if _, ok := seen[normalized]; ok {
			continue
		}
		seen[normalized] = struct{}{}
		rule.Path = path
		resolved = append(resolved, rule)
	}

	if err := wfpCall(fwpmTransactionBegin, "FwpmTransactionBegin0", m.engine, 0); err != nil {
		return m.rememberErrorLocked(err)
	}
	committed := false
	defer func() {
		if !committed {
			_, _, _ = fwpmTransactionAbort.Call(m.engine)
		}
	}()

	for key := range m.filters {
		if err := wfpCall(fwpmFilterDelete, "FwpmFilterDeleteByKey0", m.engine,
			uintptr(unsafe.Pointer(&key))); err != nil && wfpCode(err) != fwpEFilterNotFound {
			return m.rememberErrorLocked(err)
		}
	}

	newFilters := make(map[windows.GUID]nativeWFPFilter, len(resolved)*4)
	for _, rule := range resolved {
		appID, err := nativeWFPAppID(rule.Path)
		if err != nil {
			return m.rememberErrorLocked(fmt.Errorf("App ID de %q: %w", rule.Path, err))
		}
		for _, layer := range [...]windows.GUID{
			wfpLayerALEAuthConnectV4, wfpLayerALEAuthConnectV6,
			wfpLayerALEAuthRecvAcceptV4, wfpLayerALEAuthRecvAcceptV6,
		} {
			key := nativeWFPFilterKey(rule.Path, layer)
			name := utf16Ptr("AionWG BLOCK " + filepath.Base(rule.Path))
			condition := wfpFilterCondition{
				fieldKey:  wfpConditionALEAppID,
				matchType: fwpMatchEqual,
				conditionValue: wfpConditionValue{
					typeCode: fwpByteBlobType,
					value:    uintptr(unsafe.Pointer(appID)),
				},
			}
			filter := wfpFilter{
				filterKey:           key,
				displayData:         wfpDisplayData{name: uintptr(unsafe.Pointer(&name[0]))},
				providerKey:         uintptr(unsafe.Pointer(&nativeWFPProviderKey)),
				layerKey:            layer,
				subLayerKey:         nativeWFPSubLayerKey,
				weight:              wfpValue{typeCode: fwpEmpty},
				numFilterConditions: 1,
				filterCondition:     uintptr(unsafe.Pointer(&condition)),
				action:              wfpAction{typeCode: fwpActionBlock},
			}
			if err := wfpCall(fwpmFilterAdd, "FwpmFilterAdd0", m.engine,
				uintptr(unsafe.Pointer(&filter)), 0, 0); err != nil {
				runtime.KeepAlive(name)
				freeWFP(appID)
				return m.rememberErrorLocked(err)
			}
			runtime.KeepAlive(name)
			newFilters[key] = nativeWFPFilter{rule: rule, path: rule.Path}
		}
		freeWFP(appID)
	}

	if err := wfpCall(fwpmTransactionCommit, "FwpmTransactionCommit0", m.engine); err != nil {
		return m.rememberErrorLocked(err)
	}
	committed = true
	m.filters = newFilters
	m.rules = append([]ProcessRule(nil), resolved...)
	m.status.FiltersInstalled = len(newFilters)
	m.status.RulesActive = len(resolved)
	m.status.LastError = ""
	return nil
}

func (m *nativeWFPManager) ListRules() ([]ProcessRule, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.engine == 0 {
		return nil, m.rememberErrorLocked(fmt.Errorf("sessão WFP não está aberta"))
	}
	for key := range m.filters {
		present, err := m.filterPresentLocked(key)
		if err != nil {
			return nil, m.rememberErrorLocked(err)
		}
		if !present {
			return nil, m.rememberErrorLocked(fmt.Errorf("filtro WFP %v não está instalado", key))
		}
	}
	if count, err := m.enumerateOwnFiltersLocked(); err != nil {
		return nil, m.rememberErrorLocked(err)
	} else {
		m.status.FiltersInstalled = count
	}
	out := append([]ProcessRule(nil), m.rules...)
	sort.Slice(out, func(i, j int) bool { return strings.ToLower(out[i].Path) < strings.ToLower(out[j].Path) })
	return out, nil
}

func (m *nativeWFPManager) filterPresentLocked(key windows.GUID) (bool, error) {
	var filter uintptr
	err := wfpCall(fwpmFilterGetByKey, "FwpmFilterGetByKey0", m.engine,
		uintptr(unsafe.Pointer(&key)), uintptr(unsafe.Pointer(&filter)))
	if err != nil {
		if wfpCode(err) == fwpEFilterNotFound {
			return false, nil
		}
		return false, err
	}
	freeWFPPtr(filter)
	return true, nil
}

func (m *nativeWFPManager) enumerateOwnFiltersLocked() (int, error) {
	var enumHandle uintptr
	if err := wfpCall(fwpmFilterCreateEnum, "FwpmFilterCreateEnumHandle0", m.engine, 0,
		uintptr(unsafe.Pointer(&enumHandle))); err != nil {
		return 0, err
	}
	defer fwpmFilterDestroyEnum.Call(m.engine, enumHandle)

	const batchSize = 256
	owned := 0
	for {
		var entries uintptr
		var returned uint32
		if err := wfpCall(fwpmFilterEnum, "FwpmFilterEnum0", m.engine, enumHandle,
			batchSize, uintptr(unsafe.Pointer(&entries)), uintptr(unsafe.Pointer(&returned))); err != nil {
			return 0, err
		}
		if returned == 0 || entries == 0 {
			return owned, nil
		}
		rows := unsafe.Slice((*uintptr)(wfpAddressPointer(entries)), returned)
		for _, row := range rows {
			if row == 0 {
				continue
			}
			filter := (*wfpFilter)(wfpAddressPointer(row))
			if filter.providerKey != 0 && *(*windows.GUID)(wfpAddressPointer(filter.providerKey)) == nativeWFPProviderKey {
				owned++
			}
		}
		freeWFPPtr(entries)
		if returned < batchSize {
			return owned, nil
		}
	}
}

func (m *nativeWFPManager) Status() NativeWFPStatus {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.status
}

func (m *nativeWFPManager) setErrorLocked(err error) {
	m.status.LastError = err.Error()
	if m.logf != nil {
		m.logf("WFP nativo: %v", err)
	}
}

func (m *nativeWFPManager) rememberErrorLocked(err error) error {
	m.setErrorLocked(err)
	return err
}

func nativeWFPAppID(path string) (*wfpByteBlob, error) {
	name, err := windows.UTF16FromString(path)
	if err != nil {
		return nil, err
	}
	var blob *wfpByteBlob
	if err := wfpCall(fwpmGetAppID, "FwpmGetAppIdFromFileName0",
		uintptr(unsafe.Pointer(&name[0])), uintptr(unsafe.Pointer(&blob))); err != nil {
		runtime.KeepAlive(name)
		return nil, err
	}
	runtime.KeepAlive(name)
	if blob == nil {
		return nil, fmt.Errorf("FwpmGetAppIdFromFileName0 retornou App ID nulo")
	}
	return blob, nil
}

func freeWFP(blob *wfpByteBlob) {
	if blob == nil {
		return
	}
	freeWFPPtr(uintptr(unsafe.Pointer(blob)))
}

func freeWFPPtr(ptr uintptr) {
	if ptr == 0 {
		return
	}
	p := wfpAddressPointer(ptr)
	_, _, _ = fwpmFreeMemory.Call(uintptr(unsafe.Pointer(&p)))
}

// wfpAddressPointer reinterprets an address returned by fwpuclnt.dll.
func wfpAddressPointer(addr uintptr) unsafe.Pointer {
	return *(*unsafe.Pointer)(unsafe.Pointer(&addr))
}

type wfpAPIError struct {
	name string
	code uint32
}

func (e wfpAPIError) Error() string {
	return fmt.Sprintf("%s falhou: WFP 0x%08x", e.name, e.code)
}

func wfpCall(proc *windows.LazyProc, name string, args ...uintptr) error {
	code, _, _ := proc.Call(args...)
	if code == 0 {
		return nil
	}
	return wfpAPIError{name: name, code: uint32(code)}
}

func wfpCode(err error) uint32 {
	var apiErr wfpAPIError
	if errors.As(err, &apiErr) {
		return apiErr.code
	}
	return 0
}

func utf16Ptr(s string) []uint16 {
	return append(utf16.Encode([]rune(s)), 0)
}

func nativeWFPFilterKey(path string, layer windows.GUID) windows.GUID {
	input := fmt.Sprintf("aionwg:block:%s:%08x-%04x-%04x-%x", strings.ToLower(filepath.Clean(path)),
		layer.Data1, layer.Data2, layer.Data3, layer.Data4)
	sum := sha1.Sum([]byte(input))
	key := windows.GUID{
		Data1: binary.LittleEndian.Uint32(sum[0:4]),
		Data2: binary.LittleEndian.Uint16(sum[4:6]),
		Data3: binary.LittleEndian.Uint16(sum[6:8]),
	}
	copy(key.Data4[:], sum[8:16])
	key.Data3 = (key.Data3 & 0x0fff) | 0x4000
	key.Data4[0] = (key.Data4[0] & 0x3f) | 0x80
	return key
}

func resolveNativeWFPPath(rule ProcessRule) (string, error) {
	if path := strings.TrimSpace(rule.Path); path != "" {
		return existingWFPPath(path)
	}
	name := strings.TrimSpace(rule.Name)
	if name == "" {
		return "", fmt.Errorf("executável vazio")
	}
	if strings.ContainsAny(name, `:/\\`) {
		return existingWFPPath(name)
	}

	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return "", err
	}
	defer windows.CloseHandle(snap)
	var pe windows.ProcessEntry32
	pe.Size = uint32(unsafe.Sizeof(pe))
	var paths []string
	for err = windows.Process32First(snap, &pe); err == nil; err = windows.Process32Next(snap, &pe) {
		if !strings.EqualFold(windows.UTF16ToString(pe.ExeFile[:]), name) {
			continue
		}
		path, pathErr := processImagePath(pe.ProcessID)
		if pathErr == nil && !containsFold(paths, path) {
			paths = append(paths, path)
		}
	}
	if len(paths) == 0 {
		return "", fmt.Errorf("caminho completo não encontrado; abra o processo ou informe ProcessRule.Path")
	}
	if len(paths) > 1 {
		return "", fmt.Errorf("basename ambíguo; informe ProcessRule.Path")
	}
	return paths[0], nil
}

func existingWFPPath(path string) (string, error) {
	path, err := filepath.Abs(filepath.Clean(path))
	if err != nil {
		return "", err
	}
	info, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	if info.IsDir() {
		return "", fmt.Errorf("o caminho é um diretório")
	}
	return path, nil
}

func processImagePath(pid uint32) (string, error) {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return "", err
	}
	defer windows.CloseHandle(h)
	buf := make([]uint16, 32768)
	size := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(h, 0, &buf[0], &size); err != nil {
		return "", err
	}
	return windows.UTF16ToString(buf[:size]), nil
}

func containsFold(paths []string, path string) bool {
	for _, candidate := range paths {
		if strings.EqualFold(candidate, path) {
			return true
		}
	}
	return false
}
