//go:build linux

package process

func newPlatformInspector() ProcessInspector {
	return NewLinuxInspector("/proc")
}
