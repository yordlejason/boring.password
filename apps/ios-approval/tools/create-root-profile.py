#!/usr/bin/env python3
"""Package one public owner-approved CA certificate; never read or include a key."""
import argparse
import hashlib
from pathlib import Path
import plistlib
import subprocess
import uuid


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("certificate", type=Path, help="Public self-signed root CA certificate (PEM or DER)")
    parser.add_argument("output", type=Path, help="Unsigned .mobileconfig output path")
    args = parser.parse_args()
    source = args.certificate.read_bytes()
    if b"PRIVATE KEY" in source:
        raise SystemExit("Refusing input containing private key material.")
    encoding = "PEM" if b"-----BEGIN CERTIFICATE-----" in source else "DER"

    def x509(*options: str) -> bytes:
        result = subprocess.run(["openssl", "x509", "-inform", encoding, "-in", str(args.certificate), *options],
                                check=False, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        if result.returncode:
            raise SystemExit("Input must be a valid, unexpired public root CA certificate.")
        return result.stdout

    constraints = x509("-noout", "-ext", "basicConstraints").decode("utf-8")
    if "CA:TRUE" not in constraints:
        raise SystemExit("Refusing a non-CA certificate.")
    identities = x509("-noout", "-subject", "-issuer", "-nameopt", "RFC2253").decode("utf-8").splitlines()
    subject = next((line.partition("=")[2] for line in identities if line.startswith("subject=")), None)
    issuer = next((line.partition("=")[2] for line in identities if line.startswith("issuer=")), None)
    if not subject or subject != issuer:
        raise SystemExit("Refusing an intermediate certificate; supply the self-signed root.")
    x509("-noout", "-checkend", "0")
    der = x509("-outform", "DER")
    digest = hashlib.sha256(der).hexdigest()
    profile_uuid = uuid.uuid5(uuid.NAMESPACE_DNS, "login.boring.local-root." + digest)
    certificate_uuid = uuid.uuid5(profile_uuid, "certificate")
    identifier = "login.boring.approval.local-root." + digest[:16]
    name = "Boring Login — Local Development Root"
    profile = {
        "PayloadType": "Configuration",
        "PayloadVersion": 1,
        "PayloadIdentifier": identifier,
        "PayloadUUID": str(profile_uuid).upper(),
        "PayloadDisplayName": name,
        "PayloadOrganization": "Boring Login Development",
        "PayloadRemovalDisallowed": False,
        "PayloadDescription": "Installs one owner-operated certificate authority for synthetic Auth Broker testing. "
                              "Enabling SSL trust affects system-wide certificate trust. Verify the root SHA-256 "
                              "through an owner-controlled channel before installation: " + digest,
        "PayloadContent": [{
            "PayloadType": "com.apple.security.root",
            "PayloadVersion": 1,
            "PayloadIdentifier": identifier + ".certificate",
            "PayloadUUID": str(certificate_uuid).upper(),
            "PayloadDisplayName": name,
            "PayloadDescription": "Public CA certificate only. No private key or broker token is included.",
            "PayloadCertificateFileName": "boring-login-local-root.cer",
            "PayloadContent": der,
        }],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(plistlib.dumps(profile, fmt=plistlib.FMT_XML, sort_keys=True))
    args.output.with_suffix(".cer").write_bytes(der)
    print("Root certificate SHA-256:", digest)
    print("Unsigned public-certificate profile:", args.output)
    print("Installation and full SSL trust require explicit owner action on the iPhone.")


if __name__ == "__main__":
    main()
