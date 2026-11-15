package main

// NativeWFPStatus describes the user-mode policy manager, not packet capture.
type NativeWFPStatus struct {
	SessionOpen        bool
	ProviderRegistered bool
	SubLayerRegistered bool
	FiltersInstalled   int
	RulesActive        int
	LastError          string
}

type nativeWFPPolicy interface {
	Open() error
	Close()
	ReplaceRules([]ProcessRule) error
	ListRules() ([]ProcessRule, error)
	Status() NativeWFPStatus
}
