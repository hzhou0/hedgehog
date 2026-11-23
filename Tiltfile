# End-to-end environment: k3s (via k3d) with an in-cluster registry, Hedgehog from deploy/hedgehog.yaml, and the
# e2e test in e2e/. The test also needs grype on the host, at the version the Dockerfile pins.
#
#   make dev              # creates the cluster if needed, then tilt up: rebuilds on change
#   make e2e              # creates the cluster if needed, then tilt ci: exits non-zero if the e2e test fails
#   make cluster-delete

allow_k8s_contexts('k3d-hedgehog-e2e')

registry = '10.43.200.200:5000'
default_registry('localhost:5000', host_from_cluster=registry)

docker_build('hedgehog', '.', only=['go.mod', 'go.sum', 'cmd', 'internal', 'Dockerfile'])

# The install manifest as-is, except for the destination.
objs = decode_yaml_stream(read_file('deploy/hedgehog.yaml'))
for o in objs:
    if o['kind'] == 'StatefulSet':
        for e in o['spec']['template']['spec']['containers'][0]['env']:
            if e['name'] == 'DESTINATION':
                e['value'] = registry + '/patched'
k8s_yaml(encode_yaml_stream(objs))
k8s_yaml('e2e/registry.yaml')

k8s_resource('registry', labels=['infra'])
# The Pod turns Ready before the host -> k3d load balancer -> NodePort path carries traffic; wait for the path Tilt pushes over.
local_resource('registry-reachable', 'timeout 120 sh -c "until curl -sf http://localhost:5000/v2/; do sleep 1; done"',
               resource_deps=['registry'], labels=['infra'])
k8s_resource('hedgehog', resource_deps=['registry-reachable'], port_forwards=['8080'], labels=['hedgehog'])

local_resource(
    'e2e',
    'go test -tags e2e -count=1 -v -timeout 40m ./e2e',
    resource_deps=['hedgehog'],
    trigger_mode=TRIGGER_MODE_MANUAL,
    labels=['test'],
)
