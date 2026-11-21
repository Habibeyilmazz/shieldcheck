package scan

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"
)

var tlsVersions = []struct {
	id   uint16
	name string
}{
	{tls.VersionTLS10, "TLS 1.0"}, {tls.VersionTLS11, "TLS 1.1"},
	{tls.VersionTLS12, "TLS 1.2"}, {tls.VersionTLS13, "TLS 1.3"},
}

// handshake connects to addr offering only TLS versions min..max and returns
// the connection state. Certificate verification is done separately.
func (c *client) handshake(ctx context.Context, addr, host string, min, max uint16) (tls.ConnectionState, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	d := tls.Dialer{NetDialer: c.dialer, Config: &tls.Config{
		ServerName: host, MinVersion: min, MaxVersion: max,
		InsecureSkipVerify: true, // verified by verifyChain so the failure can be explained
	}}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return tls.ConnectionState{}, err
	}
	defer conn.Close()
	return conn.(*tls.Conn).ConnectionState(), nil
}

func verifyChain(certs []*x509.Certificate, host string, roots *x509.CertPool) error {
	inter := x509.NewCertPool()
	for _, c := range certs[1:] {
		inter.AddCert(c)
	}
	_, err := certs[0].Verify(x509.VerifyOptions{DNSName: host, Roots: roots, Intermediates: inter})
	return err
}

func checkTLS(ctx context.Context, c *client, u *url.URL) (*TLSInfo, []Finding) {
	if u.Scheme != "https" {
		return nil, nil // the missing HTTPS is reported by checkTransport
	}
	f := func(id string, sev Severity, title, detail, risk, advice string, fixes []Fix) Finding {
		return Finding{ID: id, Category: "tls", Severity: sev, Title: title, Detail: detail, Risk: risk, Advice: advice, Fixes: fixes}
	}
	host, port := u.Hostname(), u.Port()
	if port == "" {
		port = "443"
	}
	addr := net.JoinHostPort(host, port)

	state, err := c.handshake(ctx, addr, host, tls.VersionTLS10, tls.VersionTLS13)
	if err != nil || len(state.PeerCertificates) == 0 {
		return nil, []Finding{f("tls.unchecked", Info, "TLS could not be inspected", fmt.Sprint("Handshake with ", addr, " failed: ", err), "", "", nil)}
	}
	leaf := state.PeerCertificates[0]
	info := &TLSInfo{
		Version: tls.VersionName(state.Version), Cipher: tls.CipherSuiteName(state.CipherSuite),
		Subject: leaf.Subject.CommonName, Issuer: leaf.Issuer.CommonName,
		NotAfter: leaf.NotAfter.UTC(), DaysLeft: int(time.Until(leaf.NotAfter).Hours() / 24),
	}
	if info.Issuer == "" && len(leaf.Issuer.Organization) > 0 {
		info.Issuer = leaf.Issuer.Organization[0]
	}
	var out []Finding

	// Certificate: trust chain, hostname, validity period.
	const certRisk = "Browsers show a full-page security warning and most visitors will leave. Anyone who clicks through has no way of knowing they are talking to your server and not an impostor."
	expires := fmt.Sprintf("Issued by %s, expires %s.", info.Issuer, info.NotAfter.Format("2 Jan 2006"))
	var invalid x509.CertificateInvalidError
	var hostErr x509.HostnameError
	var unknown x509.UnknownAuthorityError
	switch err := verifyChain(state.PeerCertificates, host, c.rootCAs); {
	case err == nil && info.DaysLeft < 14:
		out = append(out, f("tls.cert-expiring", High, fmt.Sprintf("Certificate expires in %d days", info.DaysLeft), expires,
			"When the certificate expires, browsers block the site with a security warning until it is renewed.",
			"Renew it now and check why automatic renewal did not run.", certFix))
	case err == nil && info.DaysLeft < 30:
		out = append(out, f("tls.cert-expiring", Medium, fmt.Sprintf("Certificate expires in %d days", info.DaysLeft), expires,
			"When the certificate expires, browsers block the site with a security warning until it is renewed.",
			"Automatic renewal normally happens 30 days before expiry, so check that it is working.", certFix))
	case err == nil:
		out = append(out, f("tls.cert-ok", Pass, fmt.Sprintf("Certificate is valid for %d more days", info.DaysLeft), expires, "", "", nil))
	case errors.As(err, &invalid) && invalid.Reason == x509.Expired:
		out = append(out, f("tls.cert-expired", Critical, "Certificate has expired or is not yet valid", expires, certRisk, "Renew the certificate.", certFix))
	case errors.As(err, &hostErr):
		out = append(out, f("tls.cert-hostname", Critical, "Certificate does not match the hostname",
			fmt.Sprintf("The certificate is valid for %s, not for %s.", clip(strings.Join(leaf.DNSNames, ", ")), host), certRisk,
			"Issue a certificate that lists this hostname.", certFix))
	case errors.As(err, &unknown):
		out = append(out, f("tls.cert-untrusted", Critical, "Certificate chain is not trusted",
			"The chain the server sent does not lead to a trusted root. "+expires, certRisk,
			"The usual causes are a self-signed certificate, a private CA, or a server that sends its own certificate without the intermediate certificates.", certFix))
	default:
		out = append(out, f("tls.cert-invalid", Critical, "Certificate is not valid", clip(err.Error()), certRisk, "Replace the certificate.", certFix))
	}

	// Protocol versions: one ordinary handshake per version.
	accepted := map[uint16]bool{}
	for _, v := range tlsVersions {
		if _, err := c.handshake(ctx, addr, host, v.id, v.id); err == nil {
			accepted[v.id] = true
			info.Protocols = append(info.Protocols, v.name)
		}
	}
	list := "Accepted: " + strings.Join(info.Protocols, ", ") + "."
	modern := accepted[tls.VersionTLS12] || accepted[tls.VersionTLS13]
	switch {
	case accepted[tls.VersionTLS10] || accepted[tls.VersionTLS11]:
		sev := Medium
		if !modern {
			sev = High
		}
		out = append(out, f("tls.legacy-protocol", sev, "Server accepts obsolete TLS 1.0 or 1.1", list,
			"TLS 1.0 and 1.1 were retired in 2021 (RFC 8996) because of weaknesses in how they encrypt and sign data. Every current browser has dropped them, so leaving them on only helps attackers and fails compliance checks such as PCI DSS.",
			"Allow TLS 1.2 and 1.3 only.", tlsVersionFix))
	case !accepted[tls.VersionTLS13]:
		out = append(out, f("tls.no-tls13", Low, "Server does not offer TLS 1.3", list,
			"TLS 1.3 is faster to connect and removes the older cipher options that keep causing vulnerabilities in TLS 1.2.",
			"Enable TLS 1.3 alongside 1.2. This may need a newer web server or OpenSSL.", tlsVersionFix))
	default:
		out = append(out, f("tls.protocols-ok", Pass, "Only modern TLS versions are accepted", list, "", "", nil))
	}
	return info, out
}
