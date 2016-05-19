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
	"k8s.io/kubernetes/pkg/api/unversioned"
)

type PodSandboxID string

// PodSandboxManager provides basic operations to create/delete and examine the
// PodSandboxes.
type PodSandboxManager interface {
	// Create creates a sandbox based on the given config, and returns the
	//  of the new sandbox.
	Create(config *PodSandboxConfig) (PodSandboxID, error)
	// Delete deletes the sandbox by its ID. If there are any running
	// containers in the sandbox, they will be terminated as a side-effect.
	Delete(id PodSandboxID) error
	// List lists existing sandboxes, filtered by the given PodSandboxFilter.
	List(filter PodSandboxFilter) []PodSandboxListItem
	// Status gets the status of the sandbox by ID.
	Status(id PodSandboxID) (PodSandboxStatus, error)
	// PortForward copies the data from the port in the PodSandBox to the
	// stream.
	// TODO: Should PortForward be in a separate interface.
	PortForward(id PodSandboxID, port uint16, stream io.ReadWriteCloser) error
}

// PodSandboxConfig holds all the required and optional fields for creating a
// sandbox.
type PodSandboxConfig struct {
	// Name is the name of the sandbox.
	Name string
	// Hostname is the hostname of the sandbox.
	Hostname string
	// DNSOptions sets the DNS options for the sandbox.
	DNSOptions DNSOptions
	// PortMappings lists the port mappings for the sandbox.
	PortMappings []PortMapping
	// Mounts lists the mounts to be added to the sandbox's filesystem.
	Mounts []Mount
	// Resources specifies the resource requirements for the sandbox.
	// Note: On a Linux host, kubelet will create a pod-level cgroup and pass
	// it as the cgroup parent for the PodSandbox. For some runtimes, this is
	// sufficent to fulfill pod-level resource requirements, and this field
	// will not be used. For others, e.g., hypervisor-based runtimes, explicit
	// resource requirements for the sandbox are needed at creation time.
	Resources PodSandboxResources
	// Labels are key value pairs that may be used to scope and select individual resources.
	Labels Labels
	// Annotations is an unstructured key value map that may be set by external
	// tools to store and retrieve arbitrary metadata.
	Annotations map[string]string

	// Linux contains configurations specific to Linux hosts.
	Linux *LinuxPodSandboxConfig
}

// Labels are key value pairs that may be used to scope and select individual resources.
// Label keys are of the form:
//     label-key ::= prefixed-name | name
//     prefixed-name ::= prefix '/' name
//     prefix ::= DNS_SUBDOMAIN
//     name ::= DNS_LABEL
type Labels map[string]string

// LinuxPodSandboxConfig holds platform-specific configuraions for Linux
// host platforms and Linux-based containers.
type LinuxPodSandboxConfig struct {
	// CgroupParent is the parent cgroup of the sandbox.
	CgroupParent string
	// NamespaceOptions contains configurations for the sandbox's namespaces.
	// This will be used only if the PodSandbox uses namespace for isolation.
	NamespaceOptions NamespaceOptions
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
	Searches []string
}

type PodSandboxState string

const (
	// PodSandboxActive means the sandbox is functioning properly.
	PodSandboxActive PodSandboxState = "active"
	// PodSandboxInactive means the sandbox is not functioning properly.
	PodSandboxInactive PodSandboxState = "inactive"
)

// PodSandboxFilter is used to filter a list of PodSandboxes.
type PodSandboxFilter struct {
	// Name of the sandbox.
	Name string
	// ID of the sandbox.
	ID string
	// State of the sandbox.
	State string
	// LabelSelector to select matches.
	// Only api.MatchLabels is supported for now and the requirements
	// are ANDed. MatchExpressions is not supported yet.
	LabelSelector unversioned.LabelSelector
}

// PodSandboxListItem contains minimal information about a sandbox.
type PodSandboxListItem struct {
	ID    string
	State PodSandboxState
}

// PodSandboxStatus contains the status of the PodSandbox.
type PodSandboxStatus struct {
	// ID of the sandbox.
	ID string
	// State of the sandbox.
	State PodSandboxState
	// Network contains network status if network is handled by the runtime.
	Network *PodSandboxNetworkStatus
	// Status specific to a Linux sandbox.
	Linux *LinuxPodSandboxStatus
}

// PodSandboxNetworkStatus is the status of the network for a PodSandbox.
type PodSandboxNetworkStatus struct {
	IP string
}

// Namespaces contains paths to the namespaces.
type Namespaces struct {
	// Network is the path to the network namespace.
	Network string
}

// LinuxSandBoxStatus contains status specific to Linux sandboxes.
type LinuxPodSandboxStatus struct {
	// Namespaces contains paths to the sandbox's namespaces.
	Namespaces *Namespaces
}

// PodSandboxResources contains the CPU/memory resource requirements.
type PodSandboxResources struct {
	// CPU resource requirement.
	CPU api.ResourceRequirements
	// Memory resource requirement.
	Memory api.ResourceRequirements
}

// This is to distinguish with existing ContainerID type, which includes a
// runtime type prefix (e.g., docker://). We may rename this later.
type RawContainerID string

// ContainerRuntime provides methods for container lifecycle operations, as
// well as listing or inspecting existing containers.
type ContainerRuntime interface {
	// Create creates a container in the sandbox, and returns the ID
	// of the created container.
	Create(config *ContainerConfig, sandboxConfig *PodSandboxConfig, sandboxID PodSandboxID) (RawContainerID, error)
	// Start starts a created container.
	Start(RawContainerID ContainerID) error
	// Stop stops a running container with a grace period (i.e., timeout).
	Stop(RawContainerID string, timeout int) error
	// Remove removes the container.
	Remove(RawContainerID string) error
	// List lists the existing containers that match the ContainerFilter.
	// The returned list should only include containers previously created
	// by this ContainerManager.
	List(filter ContainerFilter) ([]Container, error)
	// Status returns the status of the container.
	Status(RawContainerID string) (ContainerStatus, error)
}

// ContainerCommandExecutor provides methods to run a command in the container.
// TODO: Should we merge this with ContainerRuntime?
type ContainerCommandExecutor interface {
	// Exec executes a command in the container.
	Exec(RawContainerID string, cmd []string, streamOpts StreamOptions) error
}

type ContainerConfig struct {
	// Name of the container.
	Name string
	// Image to use.
	Image ImageSpec
	// Command to execute (i.e., entrypoint for docker)
	Command []string
	// Args for the Command (i.e., command for docker)
	Args []string
	// Current working directory of the command.
	WorkingDir string
	// List of environment variable to set in the container
	Env []KeyValue
	// Mounts specifies mounts for the container
	Mounts []Mount
	// Labels are key value pairs that may be used to scope and select individual resources.
	Labels Labels
	// Annotations is an unstructured key value map that may be set by external
	// tools to store and retrieve arbitrary metadata.
	Annotations map[string]string
	// Privileged runs the container in the privileged mode.
	Privileged bool
	// ReadOnlyRootFS sets the root filesystem of the container to be
	// read-only.
	ReadOnlyRootFS bool
	// Path to store the container log on the host (i.e., outside of the
	// sandbox).
	LogPath string

	// Variables for interactive containers, these have very specialized
	// use-cases (e.g. debugging).
	// TODO: Determine if we need to continue supporting these fields that are
	// part of Kubernetes's Container Spec.
	Stdin     bool
	StdinOnce bool
	TTY       bool

	// Linux contains configuration specific to Linux containers.
	Linux *LinuxContainerConfig
}

// LinuxContainerConfig contains platform-specific configuration for
// Linux-based containers.
type LinuxContainerConfig struct {
	// Resources specification for the container.
	Resources LinuxContainerResources
	// AddCapabilities lists capabilities to add.
	AddCapabilities []string
	// DropCapabilities lists capabilities to drop.
	DropCapabilities []string
	// SELinux is the SELinux context to be applied.
	SELinux *api.SELinuxOptions
}

// LinuxContainerResources specifies Linux specific configuration for
// resources.
// TODO: Consider using Resources from opencontainers/runtime-spec/specs-go
// directly.
type LinuxContainerResources struct {
	// CPU CFS (Completely Fair Scheduler) period
	CPUPeriod uint64
	// CPU CFS (Completely Fair Scheduler) quota
	CPUQuota uint64
	// CPU shares (relative weight vs. other containers)
	CPUShares uint64
	// Memory limit in bytes
	MemoryLimitInBytes uint64
	// OOMScoreAdj specifies oom_score_adj for the container.
	OomScoreAdj int
	// Swappiness specifies hwow aggressive the kernel will swap memory pages.
	// Range from 0 to 100.
	Swappiness uint64
}

// ContainerFilter is used to filter containers.
type ContainerFilter struct {
	// Name of the container.
	Name string
	// ID of the container.
	ID string
	// State of the contianer.
	State ContainerState
	// LabelSelector to select matches.
	// Only api.MatchLabels is supported for now and the requirements
	// are ANDed. MatchExpressions is not supported yet.
	LabelSelector unversioned.LabelSelector
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

// ImageOperations offers basic image operations.
type ImageOperations interface {
	// List lists the existing images.
	List() ([]Image, error)
	// Pull pulls an image with authentication config.
	Pull(image ImageSpec, auth AuthConfig) error
	// Remove removes an image.
	Remove(image ImageSpec) error
	// Status returns the status of an image.
	Status(image ImageSpec) (Image, error)
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

// TODO: Add ContainerMetricsGetter and ImageMetricsGetter.
