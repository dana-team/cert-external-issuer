# cert-external-issuer

![Version: 0.0.0](https://img.shields.io/badge/Version-0.0.0-informational?style=flat-square) ![Type: application](https://img.shields.io/badge/Type-application-informational?style=flat-square) ![AppVersion: latest](https://img.shields.io/badge/AppVersion-latest-informational?style=flat-square)

A Helm chart for cert-external-issuer operator

## Values

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| affinity | object | `{}` | Node affinity rules for scheduling pods. Allows you to specify advanced node selection constraints. |
| approver | object | `{"clusterIssuerEnabled":false,"issuerEnabled":false,"rbacEnabled":true}` | Configuration for the cluster issuer and RBAC resources. |
| fullnameOverride | string | `""` |  |
| image.kubeRbacProxy.pullPolicy | string | `"IfNotPresent"` | The pull policy for the image. |
| image.kubeRbacProxy.repository | string | `"gcr.io/kubebuilder/kube-rbac-proxy"` | The repository of the kube-rbac-proxy container image. |
| image.kubeRbacProxy.tag | string | `"v0.16.0"` | The tag of the kube-rbac-proxy container image. |
| image.manager.pullPolicy | string | `"IfNotPresent"` | The pull policy for the image. |
| image.manager.repository | string | `"ghcr.io/dana-team/cert-external-issuer"` | The repository of the manager container image. |
| image.manager.tag | string | `""` | The tag of the manager container image. |
| issuer | object | `{"apiEndpoint":"https://test.com","certificateRestrictions":{"domainRestrictions":{"allowedDomains":["dana.com"],"allowedSubdomains":["test"]},"privateKeyRestrictions":{"allowedPrivateKeyAlgorithms":["RSA"],"allowedPrivateKeySizes":[4096]},"subjectAltNamesRestrictions":{"allowAllowedEmailSANs":false,"allowAllowedURISANs":false,"allowDNSNames":true,"allowIPAddresses":false},"subjectRestrictions":{"allowedCountries":["us"],"allowedOrganizationalUnits":["dana"],"allowedOrganizations":["dana.com"],"allowedPostalCodes":["test"],"allowedProvinces":["test"],"allowedSerialNumbers":["test"],"allowedStreetAddresses":["test"]},"usageRestrictions":{"allowedUsages":["server auth"]}},"downloadEndpoint":"https://test.com","form":"chain","httpConfig":{"retryBackoff":{"duration":"5s","steps":10},"skipVerifyTLS":true,"waitTimeout":"5s"},"name":"cert-issuer","namespace":"default"}` | Configuration for the issuers. |
| issuerSecret | object | `{"data":{"token":"placeholder"},"managed":false,"name":"cert-secret","namespace":"default"}` | Configuration for the default secret used by issuers. |
| issuerSecret.data.token | string | `"placeholder"` | Default secret token. |
| issuerSecret.managed | bool | `false` | Whether the secret is managed by the issuer or not. If this is false, the secret will not be created. |
| issuerSecret.name | string | `"cert-secret"` | Default secret name. |
| issuerSecret.namespace | string | `"default"` | Default secret namespace. |
| kubeRbacProxy | object | `{"args":["--secure-listen-address=0.0.0.0:8443","--upstream=http://127.0.0.1:8080/","--logtostderr=true","--v=0"],"ports":{"https":{"containerPort":8443,"name":"https","protocol":"TCP"}},"resources":{"limits":{"cpu":"500m","memory":"128Mi"},"requests":{"cpu":"5m","memory":"64Mi"}},"securityContext":{"allowPrivilegeEscalation":false,"capabilities":{"drop":["ALL"]}}}` | Configuration for the kube-rbac-proxy container. |
| kubeRbacProxy.args | list | `["--secure-listen-address=0.0.0.0:8443","--upstream=http://127.0.0.1:8080/","--logtostderr=true","--v=0"]` | Command-line arguments passed to the kube-rbac-proxy container. |
| kubeRbacProxy.ports | object | `{"https":{"containerPort":8443,"name":"https","protocol":"TCP"}}` | Port configurations for the kube-rbac-proxy container. |
| kubeRbacProxy.ports.https.containerPort | int | `8443` | The port for the HTTPS endpoint. |
| kubeRbacProxy.ports.https.name | string | `"https"` | The name of the HTTPS port. |
| kubeRbacProxy.ports.https.protocol | string | `"TCP"` | The protocol used by the HTTPS endpoint. |
| kubeRbacProxy.resources | object | `{"limits":{"cpu":"500m","memory":"128Mi"},"requests":{"cpu":"5m","memory":"64Mi"}}` | Resource requests and limits for the kube-rbac-proxy container. |
| kubeRbacProxy.securityContext | object | `{"allowPrivilegeEscalation":false,"capabilities":{"drop":["ALL"]}}` | Security settings for the kube-rbac-proxy container. |
| livenessProbe | object | `{"initialDelaySeconds":15,"periodSeconds":20,"port":8081}` | Configuration for the liveness probe. |
| livenessProbe.initialDelaySeconds | int | `15` | The initial delay before the liveness probe is initiated. |
| livenessProbe.periodSeconds | int | `20` | The frequency (in seconds) with which the probe will be performed. |
| livenessProbe.port | int | `8081` | The port for the health check endpoint. |
| manager | object | `{"command":["/manager"],"options":{"disableApprovedCheck":false,"ecsLogging":true,"healthProbeBindAddress":":8081","metricsBindAddress":"127.0.0.1:8080","version":false},"ports":{"health":{"containerPort":8081,"name":"health","protocol":"TCP"}},"resources":{"limits":{"cpu":"500m","memory":"128Mi"},"requests":{"cpu":"10m","memory":"64Mi"}},"securityContext":{"allowPrivilegeEscalation":false,"capabilities":{"drop":["ALL"]}}}` | Configuration for the manager container. |
| manager.options | object | `{"disableApprovedCheck":false,"ecsLogging":true,"healthProbeBindAddress":":8081","metricsBindAddress":"127.0.0.1:8080","version":false}` | Command-line commands passed to the manager container. |
| manager.ports | object | `{"health":{"containerPort":8081,"name":"health","protocol":"TCP"}}` | Port configurations for the manager container. |
| manager.ports.health.containerPort | int | `8081` | The port for the health check endpoint. |
| manager.ports.health.name | string | `"health"` | The name of the health check port. |
| manager.ports.health.protocol | string | `"TCP"` | The protocol used by the health check endpoint. |
| manager.resources | object | `{"limits":{"cpu":"500m","memory":"128Mi"},"requests":{"cpu":"10m","memory":"64Mi"}}` | Resource requests and limits for the manager container. |
| manager.securityContext | object | `{"allowPrivilegeEscalation":false,"capabilities":{"drop":["ALL"]}}` | Security settings for the manager container. |
| nameOverride | string | `""` |  |
| nodeSelector | object | `{}` | Node selector for scheduling pods. Allows you to specify node labels for pod assignment. |
| readinessProbe | object | `{"initialDelaySeconds":5,"periodSeconds":10,"port":8081}` | Configuration for the readiness probe. |
| readinessProbe.initialDelaySeconds | int | `5` | The initial delay before the readiness probe is initiated. |
| readinessProbe.periodSeconds | int | `10` | The frequency (in seconds) with which the probe will be performed. |
| readinessProbe.port | int | `8081` | The port for the readiness check endpoint. |
| replicaCount | int | `1` | The number of replicas for the deployment. |
| securityContext | object | `{}` | Pod-level security context for the entire pod. |
| service | object | `{"httpsPort":8443,"protocol":"TCP","targetPort":"https"}` | Service configuration for the operator. |
| service.httpsPort | int | `8443` | The port for the HTTPS endpoint. |
| service.protocol | string | `"TCP"` | The protocol used by the HTTPS endpoint. |
| service.targetPort | string | `"https"` | The name of the target port. |
| tolerations | list | `[]` | Node tolerations for scheduling pods. Allows the pods to be scheduled on nodes with matching taints. |

