package registry

type Hive interface {
	OpenKey(path string) (HiveKey, error)
}

type HiveKey interface {
	Name() string
	ClassName() (string, error)
	QueryValue(value string) ([]byte, error)
	EnumKey() ([]HiveKey, error)
	Close() error
}
