#!/usr/bin/env python3
"""Validate real private Firebase exports and prepare runtime files without logging keys."""
import argparse
import json
import os
from pathlib import Path
import plistlib
import shutil

ROOT = Path(__file__).resolve().parents[1]
IDENTIFIER = 'com.singheverything.crossiva'

def prepare(check_only=False):
    copies = []
    for region in ('CA', 'US', 'IN'):
        slug = region.lower()
        directory = ROOT / '.firebase' / ('ca-primary' if region == 'CA' else slug + '-secondary')
        android = directory / ('google-services.json' if region == 'CA' else 'google-services-' + slug + '.json')
        apple = directory / ('GoogleService-Info.plist' if region == 'CA' else 'GoogleService-Info-' + region + '.plist')
        a = json.loads(android.read_text())
        with apple.open('rb') as f:
            m = plistlib.load(f)
        expected = 'crossiva-dev-' + slug
        assert a['project_info']['project_id'] == m['PROJECT_ID'] == expected, 'Project mismatch'
        client, = [c for c in a['client'] if c['client_info']['android_client_info']['package_name'] == IDENTIFIER]
        assert m['BUNDLE_ID'] == IDENTIFIER, 'Bundle mismatch'
        sender = str(a['project_info']['project_number'])
        assert sender == m['GCM_SENDER_ID'], 'Sender mismatch'
        assert client['client_info']['mobilesdk_app_id'].startswith('1:' + sender + ':android:')
        assert m['GOOGLE_APP_ID'].startswith('1:' + sender + ':ios:')
        assert client['api_key'][0]['current_key'] and m['API_KEY'], 'Missing real API key'
        android_dest = ROOT / ('android/app/google-services.json' if region == 'CA' else 'android/app/src/main/assets/firebase/google-services-' + slug + '.json')
        apple_dest = ROOT / 'mac/ClipSync' / apple.name
        copies += [(android, android_dest), (apple, apple_dest)]
    for name in ('android/app/src/main/java/com/singheverything/crossiva/RegionConfig.kt', 'mac/ClipSync/RegionConfig.swift'):
        dest = ROOT / name
        copies.append((Path(str(dest) + '.example'), dest))
    for source, destination in copies:
        if check_only:
            assert destination.read_bytes() == source.read_bytes(), 'Runtime config differs: ' + str(destination.relative_to(ROOT))
        else:
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, destination)
            os.chmod(destination, 0o600)
    print('Verified CA default and US/IN secondary runtime configs; API keys not displayed.')

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true')
    prepare(parser.parse_args().check)
