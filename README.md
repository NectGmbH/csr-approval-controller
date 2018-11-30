# csr-approval-controller
Kubernetes controller for automatical approval of CertificateSigningRequests matching a specific pattern.  
Every filter passed as argument will be AND joined. Values will be regular expressions.  
  
E.g. to automatic approve all CSRs for users with the name foobar-XXX where XXX is a number:  
`./csr-approval-controller -username '^system:serviceaccount:ns:foobar-\d+$'`

## Usage
```
Usage of ./csr-approval-controller:
  -alsologtostderr
    	log to standard error as well as files
  -cn string
    	Regex filter for common name of the csr
  -dns string
    	Regex filter for dns addresses of the csr (joined by ,)
  -email string
    	Regex filter for email addresses of the csr (joined by ,)
  -groups string
    	Regex filter for groups of the csr (joined by ,)
  -ip string
    	Regex filter for ip addresses of the csr (joined by ,)
  -kubeconfig string
    	Path to a kubeconfig. Only required if out-of-cluster.
  -log_backtrace_at value
    	when logging hits line file:N, emit a stack trace
  -log_dir string
    	If non-empty, write log files in this directory
  -logtostderr
    	log to standard error instead of files
  -master string
    	The address of the Kubernetes API server. Overrides any value in kubeconfig. Only required if out-of-cluster.
  -org string
    	Regex filter for organization of the csr
  -stderrthreshold value
    	logs at or above this threshold go to stderr
  -username string
    	Regex filter for username of the csr
  -v value
    	log level for V logs
  -vmodule value
    	comma-separated list of pattern=N settings for file-filtered logging

```

## Deploy using helm
```
$ helm upgrade -i csrctrl --namespace csrctrl ./chart -f my-values.yaml
```

### Values

| Key                            | Default value                             | Description                              |
| ------------------------------ | ----------------------------------------- | ---------------------------------------- |
| csrApprovalController.image    | 'kavatech/csr-approval-controller:v1.0.0' | Image of the container                   |
| csrApprovalController.cn       | ''                                        | Common Name of the CSR to be matched     |
| csrApprovalController.org      | ''                                        | Organization of the CSR to be matched    |
| csrApprovalController.dns      | ''                                        | DNS entries of the CSR to be matched     |
| csrApprovalController.email    | ''                                        | EMail addresses of the CSR to be matched |
| csrApprovalController.ip       | ''                                        | IP addresses of the CSR to be matched    |
| csrApprovalController.groups   | ''                                        | .Spec.Groups of the CSR to be matched    |
| csrApprovalController.username | ''                                        | .Spec.Username of the CSR to be matched  |
