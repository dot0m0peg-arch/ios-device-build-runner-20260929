"""Archive, check and optionally deliver one pinned Inspect & File iPhone/iPad build."""
from argparse import ArgumentParser
from datetime import datetime, timezone
from hashlib import file_digest, sha1
import base64
import json
import os
from pathlib import Path
import plistlib
import re
import secrets
import shlex
import shutil
import subprocess
from tempfile import TemporaryDirectory
from zipfile import ZipFile

BUNDLE = "com.alphadesign.inspectandfile"
TEAM = "S5763GXRG9"
APP = "InspectAndFile"
TOOLCHAIN = {"DTXcode": "2720", "DTXcodeBuild": "27B52", "DTSDKName": "iphoneos27.2", "DTPlatformName": "iphoneos"}


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def digest(path):
    with path.open("rb") as stream:
        return file_digest(stream, "sha256").hexdigest()


def run(command, label, log, cwd=None, capture=False, timeout=360):
    result = subprocess.run(command, cwd=cwd, stdout=subprocess.PIPE if capture else log, stderr=log, timeout=timeout)
    require(result.returncode == 0, f"{label} failed. Inspect the encrypted build log.")
    return result.stdout if capture else None


def save(path, receipt):
    pending = path.with_suffix(".pending.json")
    pending.write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    pending.replace(path)


def verify_inputs(source):
    release = source / "release"
    inputs = json.loads((release / "inputs.json").read_text())
    require((inputs["app"], inputs["bundle"], inputs["team"], inputs["platform"]) == (APP, BUNDLE, TEAM, "IOS"),
            "Unexpected app identity.")
    actual = {file.relative_to(source).as_posix(): digest(file)
              for file in source.rglob("*") if file.is_file() and not file.is_relative_to(release)}
    require(actual == inputs["source_files"], "One or more frozen source members changed.")
    require(digest(release / "inspect-and-file.mobileprovision") == inputs["profile_sha256"], "Profile digest mismatch.")
    require(digest(release / "apple-distribution.cer") == inputs["certificate_sha256"], "Certificate digest mismatch.")
    return inputs


def read_profile(profile, log):
    return plistlib.loads(run(["security", "cms", "-D", "-i", str(profile)],
                              "read Apple distribution profile", log, capture=True))


def verify_distribution_profile(profile, certificate):
    entitlement = profile["Entitlements"]
    expiry = profile["ExpirationDate"]
    if expiry.tzinfo is None:
        expiry = expiry.replace(tzinfo=timezone.utc)
    require(profile.get("TeamIdentifier") == [TEAM] and expiry > datetime.now(timezone.utc)
            and entitlement.get("application-identifier") == f"{TEAM}.{BUNDLE}"
            and entitlement.get("com.apple.developer.team-identifier") == TEAM
            and not entitlement.get("get-task-allow", False)
            and not profile.get("ProvisionedDevices") and not profile.get("ProvisionsAllDevices")
            and profile.get("DeveloperCertificates") == [certificate],
            "Expected the active App Store profile for this explicit App ID and existing Apple Distribution certificate.")
    require(re.fullmatch(r"[0-9a-fA-F-]{36}", profile.get("UUID", "")) and profile.get("Name"),
            "Signing profile UUID or name is missing.")


def validate_info(info, inputs):
    expected = {"CFBundleIdentifier": BUNDLE, "CFBundleExecutable": APP,
                "CFBundleShortVersionString": inputs["version"], "CFBundleVersion": inputs["build"],
                "MinimumOSVersion": "17.0", **TOOLCHAIN}
    require(all(str(info.get(key)) == value for key, value in expected.items()) and info.get("DTSDKBuild"),
            "Device app identity, minimum OS, or SDK stamp did not match.")
    require(info.get("ITSAppUsesNonExemptEncryption") is False, "Export declaration was lost.")
    require(info.get("UIDeviceFamily") == [1, 2], "Expected iPhone and iPad families.")
    require(len(set(info.get("UISupportedInterfaceOrientations~ipad", []))) == 4, "iPad orientation support changed.")
    icon = info.get("CFBundleIcons", {}).get("CFBundlePrimaryIcon", {}).get("CFBundleIconName")
    require(icon == "AppIcon" or info.get("CFBundleIconName") == "AppIcon",
            "The native icon catalog was not compiled into the product.")
    return {**expected, "DTSDKBuild": info["DTSDKBuild"]}


def verify_app(path, inputs, log):
    info = plistlib.loads((path / "Info.plist").read_bytes())
    stamp = validate_info(info, inputs)
    require((path / "PrivacyInfo.xcprivacy").is_file() and (path / "Assets.car").is_file(),
            "The privacy manifest or asset catalog is absent.")
    require(digest(path / "PrivacyInfo.xcprivacy") == inputs["source_files"]["Resources/PrivacyInfo.xcprivacy"],
            "Bundled privacy manifest bytes changed.")
    binary = path / APP
    require(run(["xcrun", "lipo", "-archs", str(binary)], "verify device binary", log, capture=True).decode().split() == ["arm64"],
            "The device archive is not an arm64 iPhone/iPad binary.")
    linked = run(["xcrun", "vtool", "-show-build", str(binary)],
                 "verify Mach-O device build metadata", log, capture=True).decode()
    require(re.search(r"^\s+platform\s+IOS\s*$", linked, re.MULTILINE)
            and re.search(r"^\s+sdk\s+27\.2(?:\.0)?\s*$", linked, re.MULTILINE),
            "The Mach-O binary is not built for iPhoneOS SDK 27.2.")
    require(b"INSPECT_FILE_TEST_VAULT_ID" not in binary.read_bytes(), "Debug-only UI-test storage selector was compiled into Release.")
    run(["codesign", "--verify", "--deep", "--strict", str(path)], "verify Apple signature", log)
    entitlements = plistlib.loads(run(["codesign", "-d", "--entitlements", ":-", str(path)],
                                      "read iPhone/iPad entitlements", log, capture=True))
    require(entitlements.get("application-identifier") == f"{TEAM}.{BUNDLE}"
            and entitlements.get("com.apple.developer.team-identifier") == TEAM
            and not entitlements.get("get-task-allow", False), "Unexpected signed iOS entitlements.")
    return stamp


def archive(source, output):
    output.mkdir(parents=True, exist_ok=True)
    inputs = verify_inputs(source)
    receipt_path = output / "receipt.json"
    receipt = {key: inputs[key] for key in ("app", "bundle", "platform", "version", "build", "source_sha256", "app_store_record")}
    receipt.update(archive_verified=False, ipa_verified=False, validated=False, uploaded=False)
    save(receipt_path, receipt)

    p12 = base64.b64decode(os.environ.pop("APPLE_DISTRIBUTION_P12"), validate=True)
    password = os.environ.pop("APPLE_SIGNING_P12_PASSWORD")
    with (output / "device-archive.log").open("wb") as log, TemporaryDirectory(prefix="inspect-ios-sign-") as private:
        private = Path(private)
        keychain = private / "distribution.keychain-db"
        key_password = secrets.token_urlsafe(32)
        previous = []
        installed = []
        profile_path = source / "release/inspect-and-file.mobileprovision"
        certificate = (source / "release/apple-distribution.cer").read_bytes()
        profile = read_profile(profile_path, log)
        verify_distribution_profile(profile, certificate)
        fingerprint = sha1(certificate).hexdigest().upper()  # Apple signing identity lookup, not a security pin.
        p12_path = private / "distribution.p12"
        p12_path.write_bytes(p12)
        p12_path.chmod(0o600)
        try:
            previous = shlex.split(run(["security", "list-keychains", "-d", "user"],
                                        "read keychain search path", log, capture=True).decode())
            run(["security", "create-keychain", "-p", key_password, str(keychain)], "create signing keychain", log)
            run(["security", "unlock-keychain", "-p", key_password, str(keychain)], "unlock signing keychain", log)
            run(["security", "set-keychain-settings", "-lut", "7200", str(keychain)], "set keychain lifetime", log)
            run(["security", "import", str(p12_path), "-k", str(keychain), "-P", password,
                 "-T", "/usr/bin/codesign", "-T", "/usr/bin/security"], "import existing signing identity", log)
            run(["security", "set-key-partition-list", "-S", "apple-tool:,apple:,codesign:", "-s",
                 "-k", key_password, str(keychain)], "authorize Apple tools in ephemeral keychain", log)
            run(["security", "list-keychains", "-d", "user", "-s", str(keychain), *previous],
                "select ephemeral signing keychain", log)
            identities = run(["security", "find-identity", "-p", "codesigning", "-v", str(keychain)],
                             "find the existing Apple Distribution identity", log, capture=True)
            require(fingerprint.encode() in identities, "The existing P12 does not contain the approved distribution identity.")

            for directory in (Path.home() / "Library/MobileDevice/Provisioning Profiles",
                              Path.home() / "Library/Developer/Xcode/UserData/Provisioning Profiles"):
                directory.mkdir(parents=True, exist_ok=True)
                destination = directory / (profile["UUID"] + ".mobileprovision")
                if destination.exists():
                    require(digest(destination) == inputs["profile_sha256"], "A different profile already owns this UUID.")
                else:
                    shutil.copy2(profile_path, destination)
                    installed.append(destination)

            run(["xcodegen", "generate", "--spec", "project.yml"], "generate approved iOS project", log, source)
            project = source / "InspectAndFile.xcodeproj"
            archive_path = private / "InspectAndFile.xcarchive"
            run(["xcodebuild", "-project", str(project), "-scheme", APP, "-configuration", "Release",
                 "-sdk", "iphoneos", "-destination", "generic/platform=iOS", "-archivePath", str(archive_path),
                 f"DEVELOPMENT_TEAM={TEAM}", "CODE_SIGN_STYLE=Manual", f"CODE_SIGN_IDENTITY={fingerprint}",
                 f"PROVISIONING_PROFILE_SPECIFIER={profile['Name']}", "ASSETCATALOG_COMPILER_APPICON_NAME=AppIcon",
                 f"MARKETING_VERSION={inputs['version']}", f"CURRENT_PROJECT_VERSION={inputs['build']}",
                 "SKIP_INSTALL=NO", "ONLY_ACTIVE_ARCH=NO", "archive"], "archive native iPhone/iPad app", log)
            archive_app = archive_path / "Products/Applications/InspectAndFile.app"
            archive_stamp = verify_app(archive_app, inputs, log)
            receipt.update(archive_verified=True, archive_stamp=archive_stamp, profile_uuid=profile["UUID"])
            save(receipt_path, receipt)

            options = private / "ExportOptions.plist"
            options.write_bytes(plistlib.dumps({
                "method": "app-store-connect", "destination": "export", "signingStyle": "manual",
                "teamID": TEAM, "signingCertificate": fingerprint, "provisioningProfiles": {BUNDLE: profile["UUID"]},
                "manageAppVersionAndBuildNumber": False, "uploadSymbols": True,
            }))
            export = private / "export"
            run(["xcodebuild", "-exportArchive", "-archivePath", str(archive_path), "-exportPath", str(export),
                 "-exportOptionsPlist", str(options)], "export exact Apple distribution IPA", log)
            packages = list(export.glob("*.ipa"))
            require(len(packages) == 1, "Expected one exported device IPA.")
            ipa = packages[0]
            with ZipFile(ipa) as package:
                native_info = [name for name in package.namelist()
                               if re.fullmatch(r"Payload/[^/]+\.app/Info\.plist", name)]
                require(native_info == ["Payload/InspectAndFile.app/Info.plist"], "Unexpected exported iPhone/iPad app.")
            expanded = private / "exported-app"
            run(["ditto", "-x", "-k", str(ipa), str(expanded)], "expand exact IPA for independent verification", log)
            shipped = expanded / "Payload/InspectAndFile.app"
            ipa_stamp = verify_app(shipped, inputs, log)
            embedded = read_profile(shipped / "embedded.mobileprovision", log)
            verify_distribution_profile(embedded, certificate)
            require(embedded["UUID"] == profile["UUID"] and ipa_stamp == archive_stamp,
                    "Exported device package changed signer, profile or SDK identity.")
            target = output / "InspectAndFile.ipa"
            shutil.copy2(ipa, target)
            receipt.update(ipa_verified=True, ipa_stamp=ipa_stamp, package_sha256=digest(target))
            save(receipt_path, receipt)
            print("Verified signed Inspect & File iPhone/iPad device IPA. Apple upload is a separate explicit mode.")
        finally:
            for path in installed:
                path.unlink(missing_ok=True)
            if previous:
                subprocess.run(["security", "list-keychains", "-d", "user", "-s", *previous],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
            if keychain.exists():
                subprocess.run(["security", "delete-keychain", str(keychain)],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)


def deliver(source, output):
    inputs = json.loads((source / "release/inputs.json").read_text())
    path = output / "receipt.json"
    receipt = json.loads(path.read_text())
    package = output / "InspectAndFile.ipa"
    require(re.fullmatch(r"\d{6,20}", inputs.get("app_store_record", "")),
            "The existing App Store Connect record is required for this upload.")
    require(receipt["bundle"] == BUNDLE and receipt["source_sha256"] == inputs["source_sha256"]
            and receipt["app_store_record"] == inputs["app_store_record"]
            and receipt["archive_verified"] and receipt["ipa_verified"]
            and receipt["package_sha256"] == digest(package)
            and not receipt.get("upload_requested"), "The exact device archive and IPA must be independently verified first.")

    with (output / "apple-delivery.log").open("wb") as log, TemporaryDirectory(prefix="inspect-ios-upload-") as private:
        private = Path(private)
        keys = private / "private_keys"
        keys.mkdir(mode=0o700)
        key_id = os.environ.pop("APPLE_STORE_CONNECT_KEY_ID")
        issuer = os.environ.pop("APPLE_STORE_CONNECT_ISSUER_ID")
        require(re.fullmatch(r"[A-Z0-9]{10}", key_id) and re.fullmatch(r"[a-fA-F0-9-]{36}", issuer),
                "Unexpected existing App Store Connect key metadata.")
        key = keys / f"AuthKey_{key_id}.p8"
        key.write_text(os.environ.pop("APPLE_STORE_CONNECT_PRIVATE_KEY"), encoding="utf-8")
        key.chmod(0o600)
        os.environ["API_PRIVATE_KEYS_DIR"] = str(keys)
        base = ["xcrun", "altool", "-f", str(package), "--type", "ios", "--apiKey", key_id,
                "--apiIssuer", issuer, "--output-format", "json"]
        run([*base, "--validate-app"], "Apple device package validation", log, private, timeout=480)
        receipt["validated"] = True
        receipt["upload_requested"] = True
        save(path, receipt)
        run([*base, "--upload-app"], "Apple binary upload", log, private, timeout=480)
        receipt["uploaded"] = True
        save(path, receipt)
        print("Apple accepted the binary upload. Processing and private TestFlight group assignment remain separate.")


def main():
    parser = ArgumentParser()
    parser.add_argument("operation", choices=["archive", "upload"])
    parser.add_argument("source", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    if args.operation == "archive":
        archive(args.source, args.output)
    else:
        deliver(args.source, args.output)


if __name__ == "__main__":
    main()
