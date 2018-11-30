package main

import (
    "crypto/x509"
    "fmt"
    "regexp"
    "strings"

    "github.com/golang/glog"

    capi "k8s.io/api/certificates/v1beta1"
    clientset "k8s.io/client-go/kubernetes"
    certLogic "k8s.io/kubernetes/pkg/apis/certificates/v1beta1"
    cc "k8s.io/kubernetes/pkg/controller/certificates"
)

// Approver is an k8s client which is able to approve csrs matching a specific configuration.
type Approver struct {
    client   clientset.Interface
    cn       string
    org      string
    dns      string
    email    string
    ip       string
    groups   string
    username string
}

// Handle handles the passed csr by approving it when it matches the specified pattern.
func (a *Approver) Handle(csr *capi.CertificateSigningRequest) error {
    if len(csr.Status.Certificate) != 0 {
        return nil
    }

    if approved, denied := cc.GetCertApprovalCondition(&csr.Status); approved || denied {
        return nil
    }

    x509cr, err := certLogic.ParseCSR(csr)
    if err != nil {
        return fmt.Errorf("unable to parse csr %q: %v", csr.Name, err)
    }

    if !a.shouldBeHandled(csr, x509cr) {
        glog.V(2).Infof("Skipping csr `%s` since it doesn't match our pattern.", csr.Name)
        return nil
    }

    err = a.approve(csr)
    if err != nil {
        return err
    }

    return nil
}

func (a *Approver) approve(csr *capi.CertificateSigningRequest) error {
    glog.V(4).Infof("Approving CSR `%s`...", csr.Name)

    csr.Status.Conditions = append(csr.Status.Conditions, capi.CertificateSigningRequestCondition{
        Type:   capi.CertificateApproved,
        Reason: "Approved by csr-approval-controller",
    })

    _, err := a.client.CertificatesV1beta1().CertificateSigningRequests().UpdateApproval(csr)
    if err != nil {
        return fmt.Errorf("error updating approval for csr, see: %v", err)
    }

    glog.V(4).Infof("Approved CSR `%s`!", csr.Name)

    return nil
}

func (a *Approver) shouldBeHandled(csr *capi.CertificateSigningRequest, x509cr *x509.CertificateRequest) bool {
    if a.username != "" {
        usernameRegexp := regexp.MustCompile(a.username)
        if !usernameRegexp.MatchString(csr.Spec.Username) {
            glog.V(2).Infof("Not handling csr `%s` because username `%s` doesn't match regexp `%s`", csr.Name, csr.Spec.Username, a.username)
            return false
        }
    }

    if a.cn != "" {
        cnRegexp := regexp.MustCompile(a.cn)
        if !cnRegexp.MatchString(x509cr.Subject.CommonName) {
            glog.V(2).Infof("Not handling csr `%s` because cn `%s` doesn't match regexp `%s`", csr.Name, x509cr.Subject.CommonName, a.cn)
            return false
        }
    }

    if a.org != "" {
        joinedOrg := strings.Join(x509cr.Subject.Organization, ",")
        orgRegexp := regexp.MustCompile(a.org)
        if !orgRegexp.MatchString(joinedOrg) {
            glog.V(2).Infof("Not handling csr `%s` because org `%s` doesn't match regexp `%s`", csr.Name, x509cr.Subject.Organization, a.org)
            return false
        }
    }

    if a.dns != "" {
        joinedDNS := strings.Join(x509cr.DNSNames, ",")
        dnsRegexp := regexp.MustCompile(a.dns)
        if !dnsRegexp.MatchString(joinedDNS) {
            glog.V(2).Infof("Not handling csr `%s` because dns `%s` doesn't match regexp `%s`", csr.Name, joinedDNS, a.dns)
            return false
        }
    }

    if a.email != "" {
        joinedEMail := strings.Join(x509cr.EmailAddresses, ",")
        emailRegexp := regexp.MustCompile(a.email)
        if !emailRegexp.MatchString(joinedEMail) {
            glog.V(2).Infof("Not handling csr `%s` because email `%s` doesn't match regexp `%s`", csr.Name, joinedEMail, a.email)
            return false
        }
    }

    if a.groups != "" {
        joinedGroups := strings.Join(csr.Spec.Groups, ",")
        groupsRegexp := regexp.MustCompile(a.groups)
        if !groupsRegexp.MatchString(joinedGroups) {
            glog.V(2).Infof("Not handling csr `%s` because groups `%s` doesn't match regexp `%s`", csr.Name, joinedGroups, a.groups)
            return false
        }
    }

    if a.ip != "" {
        ipStrs := make([]string, len(x509cr.IPAddresses))
        for i, ip := range x509cr.IPAddresses {
            ipStrs[i] = ip.String()
        }

        joinedIPs := strings.Join(ipStrs, ",")
        ipRegexp := regexp.MustCompile(a.ip)
        if !ipRegexp.MatchString(joinedIPs) {
            glog.V(2).Infof("Not handling csr `%s` because ips `%s` doesn't match regexp `%s`", csr.Name, joinedIPs, a.ip)
            return false
        }
    }

    return true
}

// NewApprover creates a new Approver instance used to approve csrs.
func NewApprover(client clientset.Interface, cn string, org string, dns string, email string, ip string, groups string, username string) *Approver {
    return &Approver{
        client:   client,
        cn:       cn,
        org:      org,
        dns:      dns,
        email:    email,
        ip:       ip,
        groups:   groups,
        username: username,
    }
}
