package internal

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	toolscache "k8s.io/client-go/tools/cache"
	"sigs.k8s.io/controller-runtime/pkg/cache"
)

// inventory tracks which image digests run where, from the manager's Pod informer. It's rebuilt from the cluster on
// every start and never persisted. Every change signals changed, the reconcile loop's trigger.
type inventory struct {
	exclude map[string]bool // EXCLUDE_NAMESPACES: never tracked
	cache   cache.Cache     // owner lookups read ReplicaSets from it
	changed chan<- struct{}

	mu   sync.RWMutex
	pods map[types.UID]podInfo
}

// watchInventory registers the inventory on the cache's Pod informer and waits for the initial sync.
func watchInventory(ctx context.Context, c cache.Cache, exclude map[string]bool, changed chan<- struct{}) (*inventory, error) {
	inv := &inventory{exclude: exclude, cache: c, changed: changed, pods: map[types.UID]podInfo{}}
	inf, err := c.GetInformer(ctx, &corev1.Pod{})
	if err != nil {
		return nil, err
	}
	_, err = inf.AddEventHandler(toolscache.ResourceEventHandlerFuncs{
		AddFunc:    func(o any) { inv.upsert(ctx, o) },
		UpdateFunc: func(_, o any) { inv.upsert(ctx, o) },
		DeleteFunc: func(o any) { inv.remove(o) },
	})
	if err != nil {
		return nil, err
	}
	if _, err := c.GetInformer(ctx, &appsv1.ReplicaSet{}); err != nil {
		return nil, err
	}
	if !c.WaitForCacheSync(ctx) {
		return nil, errors.New("cache did not sync")
	}
	return inv, nil
}

type workload struct {
	Kind      string `json:"kind"`
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
}

func (w workload) String() string { return fmt.Sprintf("%s %s/%s", w.Kind, w.Namespace, w.Name) }

// container is one running container. For a rewritten container, Source* describe the original image.
type container struct {
	Digest       string // digest actually running
	SourceRef    string // normalised image ref from the pod spec (before any rewrite)
	SourceDigest string
	SourceImage  string // repo@digest of the original image
}

type podInfo struct {
	owner      workload
	created    time.Time
	containers []container
}

// sourceImage is the value type of sourceAnnotation (container name → original image), set on rewritten Pods.
type sourceImage struct {
	Ref    string `json:"ref"`
	Digest string `json:"digest"`
}

// usage summarises one source digest in use (including digests whose Pods were all rewritten).
type usage struct {
	Image string // repo@digest
	Users []workload
}

func (inv *inventory) upsert(ctx context.Context, o any) {
	p, ok := o.(*corev1.Pod)
	if !ok || inv.exclude[p.Namespace] {
		return
	}
	if p.Status.Phase == corev1.PodSucceeded || p.Status.Phase == corev1.PodFailed {
		inv.remove(o)
		return
	}
	// The top-level workload: Pod → ReplicaSet → Deployment/Rollout.
	owner := workload{Kind: "Pod", Namespace: p.Namespace, Name: p.Name}
	if ref := metav1.GetControllerOf(p); ref != nil {
		owner.Kind, owner.Name = ref.Kind, ref.Name
		var rs appsv1.ReplicaSet
		if ref.Kind == "ReplicaSet" && inv.cache.Get(ctx, types.NamespacedName{Namespace: p.Namespace, Name: ref.Name}, &rs) == nil {
			if o := metav1.GetControllerOf(&rs); o != nil {
				owner.Kind, owner.Name = o.Kind, o.Name
			}
		}
	}
	info := podInfo{owner: owner, created: p.CreationTimestamp.Time}
	specImage := map[string]string{}
	for _, ct := range append(p.Spec.InitContainers, p.Spec.Containers...) {
		specImage[ct.Name] = ct.Image
	}
	var sources map[string]sourceImage
	_ = json.Unmarshal([]byte(p.Annotations[sourceAnnotation]), &sources)

	for _, st := range append(p.Status.InitContainerStatuses, p.Status.ContainerStatuses...) {
		// imageID is "repo@sha256:...", sometimes with a "docker-pullable://" prefix.
		_, id, _ := strings.Cut(st.ImageID, "://")
		if id == "" {
			id = st.ImageID
		}
		running, err := name.NewDigest(id)
		if err != nil {
			continue
		}
		ctr := container{Digest: running.DigestStr(), SourceDigest: running.DigestStr(), SourceImage: running.Name()}
		ref := specImage[st.Name]
		if src, ok := sources[st.Name]; ok {
			ref, ctr.SourceDigest = src.Ref, src.Digest
		}
		r, err := name.ParseReference(ref)
		if err != nil {
			continue
		}
		ctr.SourceRef = r.Name()
		ctr.SourceImage = r.Context().Digest(ctr.SourceDigest).Name()
		info.containers = append(info.containers, ctr)
	}
	inv.mu.Lock()
	inv.pods[p.UID] = info
	inv.mu.Unlock()
	notify(inv.changed)
}

func (inv *inventory) remove(o any) {
	if d, ok := o.(toolscache.DeletedFinalStateUnknown); ok {
		o = d.Obj
	}
	if p, ok := o.(*corev1.Pod); ok {
		inv.mu.Lock()
		delete(inv.pods, p.UID)
		inv.mu.Unlock()
		notify(inv.changed)
	}
}

// usages returns every source digest in use.
func (inv *inventory) usages() map[string]usage {
	inv.mu.RLock()
	defer inv.mu.RUnlock()
	out := map[string]usage{}
	for _, p := range inv.pods {
		for _, ctr := range p.containers {
			u, ok := out[ctr.SourceDigest]
			if !ok {
				u = usage{Image: ctr.SourceImage}
			}
			if !slices.Contains(u.Users, p.owner) {
				u.Users = append(u.Users, p.owner)
			}
			out[ctr.SourceDigest] = u
		}
	}
	return out
}

// tags maps normalised tag refs (not digest refs) to the source digest they ran as.
func (inv *inventory) tags() map[string]string {
	inv.mu.RLock()
	defer inv.mu.RUnlock()
	out := map[string]string{}
	for _, p := range inv.pods {
		for _, ctr := range p.containers {
			if !strings.Contains(ctr.SourceRef, "@") {
				out[ctr.SourceRef] = ctr.SourceDigest
			}
		}
	}
	return out
}

// outdated returns the workloads with Pods running source, or an earlier patch of it, instead of its current patch,
// each with the creation time of its newest such Pod.
func (inv *inventory) outdated(source, current string) map[workload]time.Time {
	inv.mu.RLock()
	defer inv.mu.RUnlock()
	out := map[workload]time.Time{}
	for _, p := range inv.pods {
		for _, ctr := range p.containers {
			if ctr.SourceDigest == source && ctr.Digest != current && p.created.After(out[p.owner]) {
				out[p.owner] = p.created
			}
		}
	}
	return out
}

// running returns every digest a container is running (sources and patches alike).
func (inv *inventory) running() map[string]bool {
	inv.mu.RLock()
	defer inv.mu.RUnlock()
	out := map[string]bool{}
	for _, p := range inv.pods {
		for _, ctr := range p.containers {
			out[ctr.Digest] = true
		}
	}
	return out
}

// notify signals ch without blocking; ch has a buffer of one, so bursts collapse into one signal.
func notify(ch chan<- struct{}) {
	select {
	case ch <- struct{}{}:
	default:
	}
}
