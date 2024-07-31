# cert-external-issuer

This repository implements an `External Issuer` for `cert-manager` that uses the `Cert API` to issue certificates. It is based on the [`sample-external-issuer`](https://github.com/cert-manager/sample-external-issuer) example provided by `cert-manager`.

To better understand the code structure and the design decisions behind it, refer to the [`README.md`](https://github.com/cert-manager/sample-external-issuer?tab=readme-ov-file#how-to-write-your-own-external-issuer).

## Quickstart

### Prerequisites

1. A Kubernetes cluster (KinD can be used for this purpose).
2. `cert-manager` installed on the cluster (follow the [official installation guide](https://cert-manager.io/docs/installation/)).

### Deploying the Controller

You can deploy the controller either from source or by applying the `install.yaml` available on the `releases` page.

To deploy from source:

```bash
$ make deploy IMG=ghcr.io/dana-team/cert-external-issuer:<release>
```

#### Build your own image

To build and push your own image:

```bash
$ make docker-build docker-push IMG=<registry>/cert-external-issuer:<tag>
```

### Granting Permissions to the Auto Approver

`cert-manager` includes an internal approval controller that automatically approves `CertificateRequests` referencing any internal issuer type. To allow the internal approver controller to approve `CertificateRequests` that reference an `External Issuer`, additional `RBAC` permissions need to be granted. 

Refer to the [docs](https://cert-manager.io/docs/usage/certificaterequest/#approval) for more information.

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: cert-manager-controller-approve:cert-dana-io
rules:
  - apiGroups:
      - cert-manager.io
    resources:
      - signers
    verbs:
      - approve
    resourceNames:
      - issuers.cert.dana.io/*
      - clusterissuers.cert.dana.io/*
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: cert-manager-controller-approve:cert-dana-io
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cert-manager-controller-approve:cert-dana-io
subjects:
  - kind: ServiceAccount
    name: cert-manager
    namespace: cert-manager
```

### Restrictions

The API includes a `restrictions` field that defines the constraints for the `External Issuer`. `Certificate` CRs that do not meet these restrictions will not be approved, and an error message will be displayed in the corresponding `CertificateRequest` object.

### Examples

#### ClusterIssuer

```yaml
apiVersion: cert.dana.io/v1alpha1
kind: ClusterIssuer
metadata:
  name: clusterissuer-sample
spec:
  apiEndpoint: "https://test.com"
  authSecretName: "cert-secret"
  httpConfig:
    skipVerifyTLS: true
    waitTimeout: "5s"
    retryBackoff:
      duration: "5s"
      steps: 10
  form: "chain"
  certificateRestrictions:
    privateKeyRestrictions:
      allowedPrivateKeyAlgorithms:
        - RSA
      allowedPrivateKeySizes:
        - 4096
    subjectRestrictions:
      allowedOrganizations:
        - dana.com
      allowedCountries:
        - us
      allowedOrganizationalUnits:
        - dana
      allowedProvinces:
        - test
      allowedStreetAddresses:
        - test
      allowedPostalCodes:
        - test
      allowedSerialNumbers:
        - test
    usageRestrictions:
      allowedUsages:
        - server auth
    domainRestrictions:
      allowedDomains:
        - dana.com
      allowedSubdomains:
        - test
    subjectAltNamesRestrictions:
      allowDNSNames: true
      allowIPAddresses: false
      allowAllowedURISANs: false
      allowAllowedEmailSANs: false
```

#### AuthSecret

Create a `Secret` that the `Issuer`/`ClusterIssuer` references for authentication with the `Cert API`:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: cert-secret
  namespace: default
type: Opaque
data:
  token: <base64>
```

#### Certificate Example

```yaml
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: cert
  namespace: default
spec:
  secretName: cert-tls

  privateKey:
    algorithm: RSA
    encoding: PKCS1
    size: 4096

  duration: 2160h # 90d
  renewBefore: 360h # 15d

  isCA: false
  usages:
    - server auth

  subject:
    organizations:
      - dana-team
  commonName: cert.com

  dnsNames:
    - cert.com
    - www.cert.com

  issuerRef:
    name: clusterissuer-sample
    kind: ClusterIssuer
    group: cert.dana.io
```