"use strict";

const { test, describe } = require("node:test");
const assert = require("node:assert/strict");
const {
  isPublicIPv4,
  isPublicIPv6,
  isPublicAddress,
  isProhibitedHostname,
  resolveAndValidate,
  DnsSecurityError
} = require("../sus-or-bus/lib/dns");

describe("Layer B: DNS and SSRF Protection", () => {
  describe("IPv4 Boundary Validation", () => {
    test("allows standard public IPv4 addresses", () => {
      assert.equal(isPublicIPv4("93.184.216.34"), true); // example.com
      assert.equal(isPublicIPv4("8.8.8.8"), true);
      assert.equal(isPublicIPv4("1.1.1.1"), true);
    });

    test("blocks loopback 127.0.0.0/8", () => {
      assert.equal(isPublicIPv4("127.0.0.1"), false);
      assert.equal(isPublicIPv4("127.1.2.3"), false);
    });

    test("blocks private RFC 1918 ranges (10.x, 172.16-31.x, 192.168.x)", () => {
      assert.equal(isPublicIPv4("10.0.0.1"), false);
      assert.equal(isPublicIPv4("10.254.254.254"), false);
      assert.equal(isPublicIPv4("172.16.0.1"), false);
      assert.equal(isPublicIPv4("172.31.255.255"), false);
      assert.equal(isPublicIPv4("172.32.0.1"), true); // Public
      assert.equal(isPublicIPv4("192.168.1.1"), false);
    });

    test("blocks link-local and cloud metadata 169.254.169.254", () => {
      assert.equal(isPublicIPv4("169.254.169.254"), false); // AWS/GCP/Azure metadata
      assert.equal(isPublicIPv4("169.254.1.1"), false);
    });

    test("blocks carrier-grade NAT 100.64.0.0/10", () => {
      assert.equal(isPublicIPv4("100.64.0.1"), false);
      assert.equal(isPublicIPv4("100.127.255.255"), false);
      assert.equal(isPublicIPv4("100.128.0.1"), true); // Outside range
    });

    test("blocks multicast and broadcast/future-use ranges", () => {
      assert.equal(isPublicIPv4("224.0.0.1"), false);
      assert.equal(isPublicIPv4("240.0.0.1"), false);
      assert.equal(isPublicIPv4("255.255.255.255"), false);
      assert.equal(isPublicIPv4("0.0.0.0"), false);
    });
  });

  describe("IPv6 Boundary Validation", () => {
    test("allows public globally-routable unicast IPv6", () => {
      assert.equal(isPublicIPv6("2606:4700:4700::1111"), true); // Cloudflare DNS
      assert.equal(isPublicIPv6("2001:4860:4860::8888"), true); // Google DNS
    });

    test("blocks IPv6 loopback ::1 and unspecified ::", () => {
      assert.equal(isPublicIPv6("::1"), false);
      assert.equal(isPublicIPv6("::"), false);
      assert.equal(isPublicIPv6("0:0:0:0:0:0:0:1"), false);
    });

    test("blocks IPv4-mapped IPv6 pointing to private addresses", () => {
      assert.equal(isPublicIPv6("::ffff:127.0.0.1"), false);
      assert.equal(isPublicIPv6("::ffff:10.0.0.1"), false);
      assert.equal(isPublicIPv6("::ffff:169.254.169.254"), false);
      assert.equal(isPublicIPv6("0:0:0:0:0:ffff:192.168.1.1"), false);
      assert.equal(isPublicIPv6("::ffff:93.184.216.34"), true); // Mapped to public IP
    });

    test("blocks unique local (fc00::/7) and link-local (fe80::/10)", () => {
      assert.equal(isPublicIPv6("fe80::1ff:fe23:4567"), false);
      assert.equal(isPublicIPv6("fc00::1"), false);
      assert.equal(isPublicIPv6("fd12:3456:789a::1"), false);
    });

    test("blocks IPv6 documentation (2001:db8::/32)", () => {
      assert.equal(isPublicIPv6("2001:db8::1"), false);
    });
  });

  describe("Prohibited Hostnames & Resolution", () => {
    test("identifies prohibited local hostnames", () => {
      assert.equal(isProhibitedHostname("localhost"), true);
      assert.equal(isProhibitedHostname("dev.localhost"), true);
      assert.equal(isProhibitedHostname("server.local"), true);
      assert.equal(isProhibitedHostname("db.internal"), true);
      assert.equal(isProhibitedHostname("nas.lan"), true);
      assert.equal(isProhibitedHostname("example.com"), false);
    });

    test("rejects prohibited hostname via resolveAndValidate", async () => {
      await assert.rejects(
        () => resolveAndValidate("localhost"),
        { name: "DnsSecurityError", code: "PROHIBITED_HOSTNAME" }
      );
    });

    test("rejects if mock DNS answers contain private IP address", async () => {
      const mockLookup = async () => [
        { address: "10.0.0.1", family: 4 }
      ];
      await assert.rejects(
        () => resolveAndValidate("internal-service.com", mockLookup),
        { name: "DnsSecurityError", code: "SSRF_BLOCKED" }
      );
    });

    test("rejects if DNS answers contain mixed public and private IP addresses", async () => {
      const mockLookup = async () => [
        { address: "93.184.216.34", family: 4 },
        { address: "127.0.0.1", family: 4 }
      ];
      await assert.rejects(
        () => resolveAndValidate("dual-homed.com", mockLookup),
        { name: "DnsSecurityError", code: "SSRF_BLOCKED" }
      );
    });

    test("succeeds when all DNS answers are public", async () => {
      const mockLookup = async () => [
        { address: "93.184.216.34", family: 4 },
        { address: "2606:4700:4700::1111", family: 6 }
      ];
      const records = await resolveAndValidate("public-domain.com", mockLookup);
      assert.equal(records.length, 2);
      assert.equal(records[0].address, "93.184.216.34");
    });
  });
});

