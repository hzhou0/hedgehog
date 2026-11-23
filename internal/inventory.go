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

// inventory tracks which images run where, from the Pod informer. It lives in memory only.
type inventory struct {
	exclude map[string]bool
	cache   cache.Cache
	changed chan<- struct{}

	mu   sync.RWMutex
	pods map[types.UID]podInfo
}

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

// container is one running container. The Source fields describe the image before any rewrite.
type container struct {
	RunningDigest string
	RunningImage  string // repo@digest
	SourceRef     string // normalised, as written in the pod spec
	SourceDigest  string
	SourceImage   string // repo@digest
}

type podInfo struct {
	owner      workload
	created    time.Time
	containers []container
}

// sourceImage is a value of sourceAnnotation, which maps container names to their original images.
type sourceImage struct {
	Ref    string `json:"ref"`
	Digest string `json:"digest"`
}

// usage is one source digest in use, whether its Pods were rewritten or not.
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
		_, id, _ := strings.Cut(st.ImageID, "://") // drops a "docker-pullable://" prefix
		if id == "" {
			id = st.ImageID
		}
		running, err := name.NewDigest(id)
		if err != nil {
			continue
		}
		ctr := container{RunningDigest: running.DigestStr(), RunningImage: running.Name(), SourceDigest: running.DigestStr(), SourceImage: running.Name()}
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

// tagDigests maps normalised tag refs to the source digest they're running as.
func (inv *inventory) tagDigests() map[string]string {
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

// outdated returns the workloads with Pods running source (or an older patch of it) instead of patched, each with
// its newest such Pod's creation time.
func (inv *inventory) outdated(source, patched string) map[workload]time.Time {
	inv.mu.RLock()
	defer inv.mu.RUnlock()
	out := map[workload]time.Time{}
	for _, p := range inv.pods {
		for _, ctr := range p.containers {
			if ctr.SourceDigest == source && ctr.RunningDigest != patched && p.created.After(out[p.owner]) {
				out[p.owner] = p.created
			}
		}
	}
	return out
}

// runningImages maps every running digest, source or patch, to its repo@digest.
func (inv *inventory) runningImages() map[string]string {
	inv.mu.RLock()
	defer inv.mu.RUnlock()
	out := map[string]string{}
	for _, p := range inv.pods {
		for _, ctr := range p.containers {
			out[ctr.RunningDigest] = ctr.RunningImage
		}
	}
	return out
}

// notify signals ch without blocking. ch has a buffer of one, so bursts collapse.
func notify(ch chan<- struct{}) {
	select {
	case ch <- struct{}{}:
	default:
	}
}
