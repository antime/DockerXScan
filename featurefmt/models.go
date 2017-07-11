package featurefmt

// ID is only meant to be used by database implementations and should never be used for anything else.
type Model struct {
	ID int
}

type Layer struct {
	Model

	Name          string
	EngineVersion int
	Parent        *Layer
	Namespace     *Namespace
	Features      []FeatureVersion
}

type Namespace struct {
	Model

	Name          string
	VersionFormat string
}

type Feature struct {
	Model

	Name      string
	Namespace Namespace
}

type FeatureVersion struct {
	Model

	Feature    Feature
	Version    string
	// For output purposes. Only make sense when the featurefmt version is in the context of an image.
	AddedBy Layer
}

