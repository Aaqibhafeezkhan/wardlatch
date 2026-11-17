// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// Test helper only (test/never-false-safe/oracle.test.mjs O5): evaluates a saved certificate chain with Apple's Security
// framework, the trust layer Safari and URLSession use, with the SSL policy for a host name. Never in the npm package.
//   swift sectrust.swift <hostname|-> <online|offline> <chain.pem> [more.pem ...]
// "offline" forbids the evaluation any network fetch (SecTrustSetNetworkFetchAllowed false), so the answer comes from
// what is on this Mac (its trust store and Apple's valid.sqlite). SECTRUST_VERIFY_DATE (ISO 8601) evaluates as of that
// date, so a saved chain whose certificate has since expired still says what it said. Prints
// "SecTrustEvaluateWithError: true|false" and exits 0 when trusted, 1 when not, 2 when it could not evaluate.
import Foundation
import Security

let a = CommandLine.arguments
guard a.count >= 4 else { print("usage: sectrust <hostname|-> <online|offline> <chain.pem> [more.pem ...]"); exit(2) }
let host = a[1]
let online = a[2] == "online"
var certs: [SecCertificate] = []
for p in a.dropFirst(3) {
    guard let s = try? String(contentsOfFile: p, encoding: .utf8) else { print("could not read \(p)"); exit(2) }
    var b64 = ""
    var inBlock = false
    for line in s.split(separator: "\n") {
        if line.hasPrefix("-----BEGIN CERTIFICATE") { inBlock = true; b64 = ""; continue }
        if line.hasPrefix("-----END CERTIFICATE") { inBlock = false
            if let d = Data(base64Encoded: b64), let c = SecCertificateCreateWithData(nil, d as CFData) { certs.append(c) }
            continue }
        if inBlock { b64 += line.trimmingCharacters(in: .whitespaces) }
    }
}
print("certs loaded: \(certs.count)")
guard !certs.isEmpty else { exit(2) }
let policy: SecPolicy = host == "-" ? SecPolicyCreateBasicX509() : SecPolicyCreateSSL(true, host as CFString)
var trust: SecTrust?
let st = SecTrustCreateWithCertificates(certs as CFArray, policy, &trust)
guard st == errSecSuccess, let t = trust else { print("create failed \(st)"); exit(2) }
SecTrustSetNetworkFetchAllowed(t, online)
if let iso = ProcessInfo.processInfo.environment["SECTRUST_VERIFY_DATE"] {
    guard let date = ISO8601DateFormatter().date(from: iso) else { print("SECTRUST_VERIFY_DATE is not ISO 8601: \(iso)"); exit(2) }
    SecTrustSetVerifyDate(t, date as CFDate)
}
var err: CFError?
let ok = SecTrustEvaluateWithError(t, &err)
print("SecTrustEvaluateWithError: \(ok)")
if let e = err { print("error: \(e)") }
exit(ok ? 0 : 1)
