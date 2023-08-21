## Simple pod imperative way

`kubectl run nginx --image=nginx --port 80 --dry-run=oclient -oyaml`

Declarative way 

[flow chart](https://www.figma.com/file/ZUj1oFnZm1c7t6o7G8pe7h/Go-Auth?type=whiteboard&node-id=875%3A1085&t=wUumJ41oNGwluMbZ-1) :
## namespace 
```
kubectl create ns dev
kubectl create ns testing
kubectl create deploy saiyam --image=nginx
kubectl create deploy saiyam --image=nginx -n dev

```
switch the context

`kubectl config set-context --current --namespace=dev`

## Authentication 

```
kubectl config view
find the cluster name from the kubeconfig file
export CLUSTER_NAME=

export APISERVER=$(kubectl config view -o jsonpath='{.clusters[0].cluster.server}')
curl --cacert /etc/kubernetes/pki/ca.crt $APISERVER/version
```

```
curl --cacert /etc/kubernetes/pki/ca.crt $APISERVER/v1/deployments
```
The above didn't work and we need to authenticate, so let's use the first client cert

`curl --cacert /etc/kubernetes/pki/ca.crt --cert client --key key $APISERVER/apis/apps/v1/deployments`
above you can have the client and the key from the kubeconfig file

```sh
echo "<client-certificate-data_from kubeconfig>" | base64 -d > client
echo "<client-key-data_from kubeconfig>" | base64 -d > key
```

Now using the sA Token 
1.24 onwards you need to create the secret for the SA 
```
TOKEN=$(kubectl create token default)
curl --cacert /etc/kubernetes/pki/ca.crt $APISERVER/apis/apps/v1 --header "Authorization: Bearer $TOKEN"
```
from inside pod you can use `var/run/secrets/kubernetes.io/serviceaccount/token` path for the token to call the kubernetes service