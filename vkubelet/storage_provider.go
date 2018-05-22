package vkubelet

type StorageClassProvider interface {
	SupportedClasses() ([]string, error)
}