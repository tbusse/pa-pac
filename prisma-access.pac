function FindProxyForURL (url, host) {
    var resolved_ip = dnsResolve(host);

  	/* Bypass non-HTTP protocols */
  	if ((url.substring(0,5) != "http:") && (url.substring(0,6) != "https:"))
      return "DIRECT";

  	/* Bypass SAML and IdP Traffic */
    if (shExpMatch(host, "*.okta.com") ||
        shExpMatch(host, "*.acs.prismaaccess.com") ||
        shExpMatch(host, "cloud-auth.de.apps.paloaltonetworks.com") ||
        shExpMatch(host, "*.msftauth.net") ||
        shExpMatch(host, "*.msauth.net") ||
        shExpMatch(host, "*.azure.com") ||
        shExpMatch(host, "login.windows.net") ||
        shExpMatch(host, "login.microsoft.com") ||
        shExpMatch(host, "login.microsoftonline.com") ||
        shExpMatch(host, "*.access.mcas.ms") ||
        shExpMatch(host, "*.local")) {
        return "DIRECT";
    }

  	/* Bypass RFC1918 and Localhost */
    if (isInNet(resolved_ip, "10.0.0.0", "255.0.0.0") ||
        isInNet(resolved_ip, "172.16.0.0", "255.240.0.0") ||
        isInNet(resolved_ip, "192.168.0.0", "255.255.0.0") ||
        isInNet(resolved_ip, "127.0.0.0", "255.255.255.0")) {
        return "DIRECT";
    }

  	/* Bypass PAC File Distribution and Prisma Access Portal
    if (shExpMatch(host, "https://store.lab.swg.prismaaccess.com/pac/ppfdffnard/7d9dc480-3a35-44ed-b721-53ddbc1464cb.pac") ||
        shExpMatch(host, "store.lab.swg.prismaaccess.com")) {
        return "DIRECT";
    }

    /* Bypass Prisma Access Proxy */
    if (shExpMatch(host, "tbusse.proxy.lab.prismaaccess.com"))
      return "DIRECT";

  	/* Bypass Prisma GP Gateways */
  	if (shExpMatch(host, "*.gw.gpcloudservice.com"))
      return "DIRECT";

  	/* Forward anything else to Prisma Explicit Proxy */
    return "PROXY tbusse.proxy.lab.prismaaccess.com:8080";
}
