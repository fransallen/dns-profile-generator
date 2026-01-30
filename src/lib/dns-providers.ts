export interface DNSProvider {
  id: string;
  name: string;
  dohUrl: string;
  dotHostname: string;
  ips?: string[];
  description: string;
}

export const dnsProviders: DNSProvider[] = [
  {
    id: "cloudflare",
    name: "Cloudflare",
    dohUrl: "https://cloudflare-dns.com/dns-query",
    dotHostname: "one.one.one.one",
    ips: ["1.1.1.1", "1.0.0.1", "2606:4700:4700::1111", "2606:4700:4700::1001"],
    description: "Fast & privacy-focused DNS by Cloudflare",
  },
  {
    id: "google",
    name: "Google",
    dohUrl: "https://dns.google/dns-query",
    dotHostname: "dns.google",
    ips: ["8.8.8.8", "8.8.4.4", "2001:4860:4860::8888", "2001:4860:4860::8844"],
    description: "Google Public DNS with global anycast",
  },
  {
    id: "quad9",
    name: "Quad9",
    dohUrl: "https://dns.quad9.net/dns-query",
    dotHostname: "dns.quad9.net",
    ips: ["9.9.9.9", "149.112.112.112", "2620:fe::fe", "2620:fe::9"],
    description: "Security-focused DNS with threat blocking",
  },
  {
    id: "adguard",
    name: "AdGuard",
    dohUrl: "https://dns.adguard-dns.com/dns-query",
    dotHostname: "dns.adguard-dns.com",
    ips: ["94.140.14.14", "94.140.15.15"],
    description: "Ad-blocking DNS by AdGuard",
  },
  {
    id: "custom",
    name: "Custom",
    dohUrl: "",
    dotHostname: "",
    description: "Configure your own DNS server",
  },
];
