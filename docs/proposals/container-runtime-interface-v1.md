# Redefine Container Runtime Interface

## Motivation

Kubelet employs a declarative pod-level interface, which acts as the sole
integration point for container runtimes (e.g., `docker` and `rkt`). The
high-level, declarative interface has caused higher integration and maintenance
cost, and also slowed down feature velocity for the following reasons.
  1. **Not every container runtime supports the concept of pods natively**.
     When integrating with Kubernetes, a significant amount of work needs to
     go into implementing a shim of significant size to support all pod
     features. This also adds maintenance overhead (e.g., `docker`).
  2. **High-level interface discourage code sharing and reuse among runtimes**.
     E.g, each runtime implements an all-encompassing `SyncPod()` function that
     (re-)starts pods/containers and manage lifecycle hooks.
  3. **Pod Spec is susceptible to inconsistent interpretations**. E.g., `rkt`
     does not support container-level operations and assume immutable pods.
  4. **Pod Spec is evolving rapidly**. New features are being added constantly.
     Any pod-level change or addition requires changing of all container
     runtime shims. E.g., init containers and volume containers.

## Goals and Non-Goals

The goals of defining the interface are to
 - **improve extensibility**: Easier container runtime integration.
 - **improve feature velocity**
 - **improve code maintainability**

The non-goals include
 - proposing *how* to integrate with new runtimes, i.e., where the shim
   resides. The discussion of adopting a client-server architecture is tracked
   by [#13768](https://issues.k8s.io/13768), where benefits and shortcomings of
   such an architecture is discussed.
 - adding support to Windows containers. Windows container support is a
   parallel effort and is tracked by [#22623](https://issues.k8s.io/22623). The
   new interface will leave room for future integration, but will
 - re-defining Kubelet's internal interfaces. These interfaces, though, may affect
   Kubelet's maintainability, is not relevant to runtime integration's.

## Requirements

 * Support existing integrated container runtimes
 * Support hypervisor-based container runtimes

## Container Runtime Interface

The main idea of the proposal is to adopt an imperative container-level
interface, which allows Kubelet to control the lifecycles of the containers
inside a pod, across all container runtimes. A separate PodSandbox is concept
is defined to represent the environment in which a group of containers in a
pod will be created and run. The container runtimes may interpret the sandbox
concept differently based on how it operates internally. For runtimes relying
on hypervisor, sandbox represents a virtual machine. For others, it can be a
container holding the namespaces.

In short, a PodSandbox should have the following features.

 * **Isolation**: E.g., Linux namespaces or a full virtual machine, or even
   support additional security features.
 * **Resource requirements**: A sandbox should implement pod-level resource
   requirements.

A container in a PodSandbox maps to a application in the Pod Spec. For Linux
containers, they are expected to share at least network and IPC namespaces,
with sharing more namespaces discussed in [#1615](https://issues.k8s.io/1615).


Below is an example of the proposed interfaces.
```go
// PodSandboxManager contains basic operations for sandbox.
type PodSandboxManager interface {
	Create(config *PodSandboxConfig) (string, error)
	Delete(id string) (string, error)
	List(filter PodSandboxFilter) []PodSandboxListItem
	Inspect(id string) PodSandbox
}

// ContainerRuntime contains basic operations for containers.
type ContainerRuntime interface {
    Create(config *ContainerConfig, sandboxConfig *PodSandboxConfig, sandboxIDng) (string, error)
    Start(id string) error
    Stop(id string, timeout int) error
    Remove(id string) error
    List(filter ContainerFilter) ([]ContainerListItem, error)
    Inspect(id string) (Container, error)
}

// ContainerCommandExecutor provides methods to run commands in a container.
type ContainerCommandExecutor interface {
	Exec(id string, cmd []string, streamOpts StreamOptions) error
}

// ImageOperations contains image-related operations.
type ImageOperations interface {
	List() ([]Image, error)
	Pull(image ImageSpec, auth AuthConfig) error
	Remove(image ImageSpec) error
	Inspect(image ImageSpec) (Image, error)
}

type PodSandboxMetricsGetter interface {
    ContainerMetrics(id string) (ContainerMetrics, error)
}

type ContainerMetricsGetter interface {
    ContainerMetrics(id string) (ContainerMetrics, error)
}

type ImageMetricsGetter interface {
    ImageMetrics(id string) (ImageMetrics, error)
}
```

### Pod Lifecycle

The sandbox’s lifecycle is decoupled from the containers, i.e., a sandbox
is created before any containers, and can exist after all containers in it have
terminated.

Assume there is a pod with a single container C. To start a pod:
```
  create sandbox Foo --> create container C --> start container C
```

To delete a pod:
```
  stop container C --> remove container C --> delete sandbox Foo
```

Kubelet is responsible for creating, starting the containers based on the
pod-level restart policy. E.g., if container C dies unexpectedly, Kubelet
will simply create and start the container again in sandbox Foo.

Kubelet is also responsible for gracefully terminating all the containers
in the sandbox before deleting the sandbox. If Kubelet chooses to delete
the sandbox with running containers in it, those containers may be forcibly
deleted.

### Updates to PodSandbox or Containers

Kubernetes support updates only to a very limited set of fields in the Pod
Spec.  These updates may require containers to be re-created by Kubelet. This
can be achieved through the imperative container-level interface. On the other
hand, sandbox update currently is not required.


### Container Lifecycle Hooks

Kubernetes supports post-start and pre-stop lifecycle hooks, with ongoing
discussion for supporting pre-start and post-stop hooks in
[#140](https://issues.k8s.io/140).

These lifecycle hooks will be implemented by Kubelet via `Exec` calls to the
container runtime. This frees the runtimes from having to support hooks
natively.

Illustration of the container lifecycle and hooks:

```
            pre-start post-start    pre-stop post-stop
               |        |              |       |
              exec     exec           exec    exec
               |        |              |       |
 create --------> start ----------------> stop --------> remove
```

## Alternatives

**[Status quo] Declarative pod-level interface**
 - Pros: No changes needed.
 - Cons: All the issues stated in #motivation

**Allow integration at both pod- and container-level interfaces**
 - Pros: Flexibility.
 - Cons: All the issues stated in #motivation

**Imperative pod-level interface**
The interface contains only CreatePod(), StartPod(), StopPod() and RemovePod().
 - Pros: Kubelet can potentially become a very thin daemon; lower maintenance
    overhead for the Kubernetes maintainers.
 - Cons: Higher integration cost and lower feature velocity.

