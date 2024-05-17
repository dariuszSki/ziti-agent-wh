# ziti-agent-wh

To deploy to your cluster for testing:

***Note: All resources in the spec are configured for namespace `ziti`. One can replace it with his/her own namespace by replacing `ziti` with a new one. `metadata: namespace: ziti`. The webhook container was precreated for the testing and it is already configured in the deployment spec `docker.io/elblag91/ziti-agent-wh:1.0.3`. The Identity Role Attribute is set to the app name in this current version and it is not configurable right now.***

Update the secret and config map templates with the ziti controller password/username/DNS-IP-name in the webhook spec file.
```bash
# secret
data:
   username: "{base64|your_value}"
   password: "{base64|your_value}"


# configmap
data:
   address: "{https://your_fqdn:port}"
```

Update the the rest of deployment env vars as needed:
```bash
env:
    - name: POD_SECURITY_CONTEXT_OVERRIDE
      value: "false"
    - name: CLUSTER_DNS_SVC_IP
      value: "10.96.0.10"
    - name: SEARCH_DOMAIN_LIST
      value: "ziti,sidecar.svc"
```

Run the spec
```bash
kubectl -f sidecar-injection-webhook-spec.yaml --context $CLUSTER
```

Once the webhook has been deployed successfully, one can enable injection per namespace by adding label `openziti/ziti-tunnel=enabled`
```bash
kubectl label namespace {ns name} openziti/ziti-tunnel=enabled --context $CLUSTER3
```

if resources are already deployed in this namespace, one can run this to restart all pods per deployment.
```bash
kubectl rollout restart deployment/{appname} -n {ns name} --context $CLUSTER 
```
