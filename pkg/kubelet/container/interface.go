/*
Copyright 2016 The Kubernetes Authors All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package container

import (
	"io"

	"k8s.io/kubernetes/pkg/api"
)

// SandboxManager provides basic operations to create/delete and examine the
// Sandboxes.
type SandboxManager interface {
	// Create creates a sandbox based on the given config, and returns the ID
	// of the new sandbox.
	Create(config *SandboxConfig) (string, error)
	// Delete deletes the sandbox with by its ID. If there are any running
	// containers in the sandbox, they will be terminated as a side-effect.
	Delete(id string) (string, error)
	// List lists existing sandboxes, filtered by the given SandboxFilter.
	List(filter SandboxFilter) []SandboxListItem
	// Inspect gets the detailed config and status of the sandbox by ID.
	Inspect(id string) Sandbox
}

// SandboxConfig holds all the required and optional fields for creating a
// sandbox.
type SandboxConfig struct {
	// Name is the name of the sandbox.
	Name string
	// Hostname is the hostname of the sandbox.
	Hostname string
	// DNSOptions the DNS configuration the sandbox.
	DNSOptions *DNSOptions
	// PortMappings lists the port mappings for the sandbox.
	PortMappings []PortMapping
	// Mounts list the mounts to be added to the sandbox's filesystem.
	Mounts []Mount
	// Resources specifies the resource requirements for the sandbox.
	Resources *Resources
	// Annotations is an unstructured key value map that may be set by external
	// tools to store and retrieve arbitrary metadata.
	Annotations map[string]string
	// Linux contains configurations specific to Linux containers.
	Linux *LinuxSandboxConfig
}

// LinuxSandboxConfig holds platform-specific configuraions for Linux
// containers.
type LinuxSandboxConfig struct {
	// CgroupParent is the parent cgroup of the sandbox.
	CgroupParent string
	// NamespaceOptions contains configurations for the sanbox's namespaces.
	NamespaceOptions NamespaceOptions
	// SELinux is the SELinux context to be applied to all containers.
	SELinux *api.SELinuxOptions
}

// NamespaceOptions provides options for Linux namespaces.
type NamespaceOptions struct {
	// HostNetwork uses the host's network namespace.
	HostNetwork bool
	// HostPID uses the host's pid namesapce.
	HostPID bool
	// HostIPC uses the host's ipc namespace.
	HostIPC bool
}

// DNSOptions specifies the DNS servers and search domains.
type DNSOptions struct {
	// Servers is a list of DNS servers of the cluster.
	Servers []string
	// Searches is a list of DNS search domains of the cluster.
	Searchs []string
}

type SandboxState string

const (
	// SandboxActive means the sandbox is functioning properly.
	SandboxActive SandboxState = "active"
	// SandboxInactive means the sandbox is not functioning properly.
	SandboxInactive SandboxState = "inactive"
)

// SandboxFilter is used to filter a list of Sandboxes.
type SandboxFilter struct {
	// Name of the sandbox.
	Name string
	// ID of the sandbox.
	ID string
	// State of the sandbox.
	State string
	// Annotations of the sandbox. A container needs to have all listed
	// annotations to be sandbox a match.
	Annotations map[string]string
}

// SandboxListItem contains minimal information about a sandbox.
type SandboxListItem struct {
	ID    string
	State SandboxState
}

// Sandbox provides isolation with resource requirements in which containers
// can be run.
type Sandbox struct {
	// ID of the sandbox.
	ID string
	// Config of the sandbox used to create the sandbox.
	Config SandboxConfig
	// Status of the sandbox.
	Status SandboxStatus
}

// SandboxStatus contains the status of the sandbox.
type SandboxStatus struct {
	// State of the sandbox.
	State SandboxState
	// Network contains network status if network is handled by the runtime.
	Network *SandboxNetworkStatus
	// Status specific to a Linux sandbox.
	Linux *LinuxSandboxStatus
}

type SandboxNetworkStatus struct {
	IP string
}

// Namespaces contains paths to the namespaces.
type Namespaces struct {
	// Network is the path to the network namespace.
	Network string
}

// LinuxSandBoxStatus contains status specific to Linux sandboxes.
type LinuxSandboxStatus struct {
	// Namespaces contains paths to the sandbox's namespaces.
	Namespaces *Namespaces
}

// Resources contains the CPU/memory resource requirements.
type Resources struct {
	// CPU resource requirement.
	CPU api.ResourceRequirements
	// Memory resource requirement.
	Memory api.ResourceRequirements
}

// ContainerRuntime provides methods for container lifecycle operations, as
// well as listing or inspecting existing containers.
type ContainerRuntime interface {
	// Create creates a container in the sandbox, and returns the ID of hte
	// created container.
	Create(config *ContainerConfig, sandboxConfig *SandboxConfig, sandboxID string) (string, error)
	// Start starts a created container.
	Start(id string) error
	// Stop stops a running container with a grace period (i.e., timeout).
	Stop(id string, timeout int) error
	// Remove removes the container.
	Remove(id string) error
	// List lists the existing containers that matches the ContainerFilter.
	List(filter ContainerFilter) ([]Container, error)
	// Inspect returns the detailed status of the container.
	Inspect(id string) (ContainerInspectResult, error)
}

// ContainerCommandExecutor provides methods to run a command in the container.
// TODO: Should we merge this with ContainerRuntime?
type ContainerCommandExecutor interface {
	// Exec executes a command in the container.
	Exec(id string, cmd []string, streamOpts StreamOptions) error
}

// ContainerInspectResult contains the detailed config and status for a
// container.
type ContainerInspectResult struct {
	// ID of the container.
	ID string
	// Config of the container.
	Config ContainerConfig
	// Status of the container.
	// TODO: Re-examine ContainerStatus and consolidate the fields.
	Status ContainerStatus
}

type ContainerConfig struct {
	// Name of the container.
	Name string
	// Image to use.
	Image ImageSpec
	// RootFSPath is the path to the root filesystem. This field is optional.
	// If not set, the runtime should create the root filesystem itself.
	RootFSPath *string
	// Command to execute (i.e., entrypoint for docker)
	Command []string
	// Args for the Command (i.e., command for docker)
	Args []string
	// Current working directory of the command.
	WorkingDir string
	// List of environment variable to set in the container
	Env []KeyValue
	// Annotations is an unstructured key value map that may be set by external
	// tools to store and retrieve arbitrary metadata.
	Annotations map[string]string
	// Mount specifies mounts for the container
	Mounts []Mount
	// Privileged runs the container in the privileged mode.
	Privileged bool
	// ReadOnlyRootFS sets the root filesystem of the container to be
	// read-only.
	ReadOnlyRootFS bool
	// Linux contains configuration specific to Linux containers.
	Linux *LinuxContainerConfig
	// Path to store the container log on the host (i.e., outside of the
	// sandbox).
	LogPath string
}

// LinuxContainerConfig contains configurations speicifc to Linux containers.
type LinuxContainerConfig struct {
	// AddCapabilities lists capabilities to add.
	AddCapabilities []string
	// DropCapabilities lists capabilities to drop.
	DropCapabilities []string
}

// ContainerFilter is used to filter containers.
type ContainerFilter struct {
	// Name of the container.
	Name string
	// ID of the container.
	ID string
	// State of the contianer.
	State ContainerState
	// Annotations of the container. A container needs to have all listed
	// annotations to be considered a match.
	Annotations map[string]string
}

type StreamOptions struct {
	TTY          bool
	InputStream  io.Reader
	OutputStream io.Writer
	ErrorStream  io.Writer
}

// KeyValue represents a key-value pair.
type KeyValue struct {
	Key   string
	Value string
}

// ImageManager offers basic image operations.
// TODO: Need a better name.
type ImageManager interface {
	// List lists the existing images.
	List() ([]Image, error)
	// Pull pulls an image with authentication config.
	Pull(image ImageSpec, auth AuthConfig) error
	// Remove removes an image.
	Remove(image ImageSpec) error
	// Inspect inspects an image.
	Inspect(image ImageSpec) (Image, error)
}

// AuthConfig contains authorization information for connecting to a registry.
// TODO: This is copied from docker's Authconfig. We should re-evaluate to
// support other registries.
type AuthConfig struct {
	Username      string
	Password      string
	Auth          string
	ServerAddress string
	// IdentityToken is used to authenticate the user and get
	// an access token for the registry.
	IdentityToken string
	// RegistryToken is a bearer token to be sent to a registry
	RegistryToken string
}

// TODO: Define metrics for Sandbox, Container, and Image.
