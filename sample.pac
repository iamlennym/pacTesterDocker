
function FindProxyForURL(url, host) {

	//        ****************************************************************************
	//        This is an example PAC file that should be edited prior to being put to use.
	//        ****************************************************************************
	    
	//        Consider the following:
	//         - Keep production PAC files small. Delete all comments if possible
	//         - Delete any examples or sections that do not fit your needs
	//         - Consolidate bypass criteria into fewer if() statements if possible
	//         - Be sure you are bypassing only traffic that *must* be bypassed
	//         - Be sure to not perform any DNS resolution in the PAC
	//         - Zscaler recommends sending bypassed internet traffic via on-premise proxy compared
	//           to the internet directly

	//        ====== Section I ==== Internal/Specific Destinations ============================== 

	//        Most special use IPv4 addresses (RFC 5735) defined within this regex.
	var privateIP = /^(0|10|127|192\.168|172\.1[6789]|172\.2[0-9]|172\.3[01]|169\.254|192\.88\.99)\.[0-9.]+$/;
	var resolved_ip = dnsResolve(host);

	/* Don't send non-FQDN or private IP auths to us */
	if (isInNet(resolved_ip, "192.0.2.0","255.255.255.0") || privateIP.test(resolved_ip))
	      return "DIRECT";

	// IP Range exclusions
	if ( isInNet(resolved_ip, "10.0.0.0", "255.0.0.0") ||
		isInNet(resolved_ip, "137.117.102.0", "255.255.255.0") ||
		isInNet(resolved_ip, "162.13.0.0", "255.255.0.0") ||
		isInNet(resolved_ip, "172.0.0.0", "255.0.0.0") ||
		isInNet(resolved_ip, "172.18.0.0", "255.255.0.0") ||
		isInNet(resolved_ip, "172.19.0.0", "255.255.0.0") ||
		isInNet(resolved_ip, "172.20.224.0", "255.255.255.0") ||
		isInNet(resolved_ip, "172.25.0.0", "255.255.0.0") ||
		isInNet(resolved_ip, "172.25.15.0", "255.255.255.0") ||
		isInNet(resolved_ip, "192.168.0.0", "255.255.0.0") ||
		isInNet(resolved_ip, "192.168.51.0", "255.255.255.0") ||
		isInNet(resolved_ip, "192.168.52.0", "255.255.255.0") ||
		isInNet(resolved_ip, "192.234.10.0", "255.255.255.0") )
		return "DIRECT";


	// Individual IP exclusions
	if ( isInNet(resolved_ip, "10.100.133.177", "255.255.255.255") ||
		isInNet(resolved_ip, "100.64.114.30", "255.255.255.255") ||
		isInNet(resolved_ip, "100.64.194.206", "255.255.255.255") ||
		isInNet(resolved_ip, "100.64.49.201", "255.255.255.255") ||
		isInNet(resolved_ip, "100.64.51.50", "255.255.255.255") ||
		isInNet(resolved_ip, "129.121.17.216", "255.255.255.255") ||
		isInNet(resolved_ip, "172.18.192.100", "255.255.255.255") ||
		isInNet(resolved_ip, "192.168.52.77", "255.255.255.255") ||
		isInNet(resolved_ip, "192.234.10.203", "255.255.255.255") ||
		isInNet(resolved_ip, "192.234.10.204", "255.255.255.255") ||
		isInNet(resolved_ip, "192.234.10.206", "255.255.255.255") ||
		isInNet(resolved_ip, "192.234.10.211", "255.255.255.255") ||
		isInNet(resolved_ip, "196.10.228.48", "255.255.255.255") ||
		isInNet(resolved_ip, "37.59.137.243", "255.255.255.255") ||
		isInNet(resolved_ip, "52.11.165.90", "255.255.255.255") ||
		isInNet(resolved_ip, "52.34.66.176", "255.255.255.255") ||
		isInNet(resolved_ip, "52.88.244.78", "255.255.255.255") ||
		isInNet(resolved_ip, "62.173.32.50", "255.255.255.255") ||
		isInNet(resolved_ip, "62.173.36.139", "255.255.255.255") )
		return "DIRECT";


    
	//      Specific destinations can be bypassed here.
	//	Also bypass plain host names (without domain).
	//	Also possible to match direct host and domain like this : (host == "host.example.com") ||
	if ( isPlainHostName(host) || 
		shExpMatch(host, "go.dev") ||
		shExpMatch(host, "*.bank3d.ng") ||
		shExpMatch(host, "*.citrix.local") ||
		shExpMatch(host, "*.cp.thomsonreuters.com") ||
		shExpMatch(host, "*.cybersoc.deloitte.es") ||
		shExpMatch(host, "*.network.global") ||
		shExpMatch(host, "*.remita.net") ||
		shExpMatch(host, "*.thomsonreuters.net") ||
		shExpMatch(host, "*.xpresspayments.com") ||
		shExpMatch(host, "*bridge-sample.aavaz.biz") ||
		shExpMatch(host, "*finacleng.samplegroup.com") ||
		shExpMatch(host, "*grp*.samplegroup.com") ||
		shExpMatch(host, "*instantbillspay.com") ||
		shExpMatch(host, "*reports2.gtplimited.com") ||
		shExpMatch(host, "*sample.aavaz.biz") ||
		shExpMatch(host, "*samplemarketplace.com") ||
		shExpMatch(host, "HQ-VM-EXP*") ||
		shExpMatch(host, "a*.samplegroup.com") ||
		shExpMatch(host, "accttxn.*") ||
		shExpMatch(host, "acstest.unifiedpaymentsnigeria.com") ||
		shExpMatch(host, "agentpc.westernunion.com") ||
		shExpMatch(host, "apps.cooperativemanager.com") ||
		shExpMatch(host, "asset-web") ||
		shExpMatch(host, "autodiscover.outlook.com") ||
		shExpMatch(host, "autodiscover.samplegroup.com") ||
		shExpMatch(host, "autodiscover.samplegroup.mail.onmicrosoft.com") ||
		shExpMatch(host, "b*.samplegroup.com") ||
		shExpMatch(host, "c*.samplegroup.com") ||
		shExpMatch(host, "cib.samplegroup.com*") ||
		shExpMatch(host, "d*.samplegroup.com") ||
		shExpMatch(host, "databaseendsrv.cloudapp.net") ||
		shExpMatch(host, "e*.samplegroup.com") ||
		shExpMatch(host, "ecashier.com") ||
		shExpMatch(host, "entrust12plugin1.samplegroup.com:8443") ||
		shExpMatch(host, "epay.cloudapp.net") ||
		shExpMatch(host, "fb*.samplegroup.com") ||
		shExpMatch(host, "fin*.*") ||
		shExpMatch(host, "g*.samplegroup.com*") ||
		shExpMatch(host, "gtpportal.com*") ||
		shExpMatch(host, "hcmportal") ||
		shExpMatch(host, "hq*.samplegroup.com") ||
		shExpMatch(host, "ibank.samplegroup.com") ||
		shExpMatch(host, "ibm-apm.samplegroup.com") ||
		shExpMatch(host, "ice.samplegroup.com*") ||
		shExpMatch(host, "idealab.samplegroup.com") ||
		shExpMatch(host, "k*.samplegroup.com") ||
		shExpMatch(host, "mail.samplegroup.com") ||
		shExpMatch(host, "mybankcardportal*") ||
		shExpMatch(host, "n*.samplegroup.com") ||
		shExpMatch(host, "nip") ||
		shExpMatch(host, "o*.samplegroup.com") ||
		shExpMatch(host, "obank.samplegroup.com") ||
		shExpMatch(host, "portal.unifiedpaymentsnigeria.com") ||
		shExpMatch(host, "portuguesesit.samplegroup.com") ||
		shExpMatch(host, "prime.samplegroup.com") ||
		shExpMatch(host, "processapp.samplegroup.com") ||
		shExpMatch(host, "r*.samplegroup.com") ||
		shExpMatch(host, "reportserver.samplegroup.com") ||
		shExpMatch(host, "s*.samplegroup.com") ||
		shExpMatch(host, "samplegroup.mail.onmicrosoft.com") ||
		shExpMatch(host, "samplemarketplace.com") ||
		shExpMatch(host, "samplespmp*") ||
		shExpMatch(host, "sandbox.samplegroup.com") ||
		shExpMatch(host, "ssm.samplegroup.com") ||
		shExpMatch(host, "t*.samplegroup.com") ||
		shExpMatch(host, "trade") ||
		shExpMatch(host, "tunsample.warime.com") ||
		shExpMatch(host, "u*.samplegroup.com") ||
		shExpMatch(host, "utctrade") ||
		shExpMatch(host, "v*.samplegroup.com") ||
		shExpMatch(host, "vm-hq-con-colet.samplegroup.com") ||
		shExpMatch(host, "vm-sc-identity*") ||
		shExpMatch(host, "www.gtpsecurecard.com") ||
		shExpMatch(host, "www.samplemarketplace.com") )
		return "DIRECT";

    
	//        If you have a website that is hosted both internally and externally,
	//        and you want to bypass proxy for internal version only, use the following

	//        if (shExpMatch(host, "internal.example.com"))
	//        {
	//                var resolved_ip = dnsResolve(host);
	//                if (privateIP.test(resolved_ip))
	//                        return "DIRECT";
	//        }

	//        ====== Section II ==== Special Bypasses for SAML============================== 
	//        if (shExpMatch(host, "*.okta.com") || shExpMatch(host, "*.oktacdn.com"))
	//                return "DIRECT";
	    
	//        if (shExpMatch(host, "my_iwa_server.my_example_domain.com"))
	//                return "DIRECT";

	//        ====== Section III ==== Bypasses for other protocols ============================
	//        Send everything other than HTTP and HTTPS direct
	//        Uncomment middle line if FTP over HTTP is enabled

	if ((url.substring(0,5) != "http:") &&
	//                (url.substring(0,4) != "ftp:") &&
	      (url.substring(0,6) != "https:"))
	      return "DIRECT";

	//        ====== Section IV ==== Bypasses for Zscaler ===================================
	//        Go direct for queries about Zscaler infrastructure status 
	var trust = /^(trust|ips).(zscaler|zscalerone|zscalertwo|zscalerthree|zsdemo|zscalergov|zscloud|zsfalcon|zdxcloud|zdxpreview|zdxbeta|zspreview|zsdevel|zsbetagov|zscalerten|zdxten).(com|net)$/;
	if (trust.test(host)) 
	      return "DIRECT";

	//        ====== Section V ==== Bypasses for ZPA ===================================
	/* test with ZPA*/
	if (isInNet(resolved_ip, "100.64.0.0","255.255.0.0"))
	      return "DIRECT";

	//        ====== Section VI ==== DEFAULT FORWARDING ================================ 

	//        If your company has purchased dedicated port, kindly use that in this file.
	//        Port 9400 is the default port followed by 80. If that does not resolve, we send directly:

	return "PROXY ${GATEWAY}:9400; PROXY ${SECONDARY_GATEWAY}:9400; PROXY ${GATEWAY}:80; PROXY ${SECONDARY_GATEWAY}:80; DIRECT";
}
