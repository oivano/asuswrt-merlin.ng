#!/usr/bin/python3
import re
import argparse
from datetime import date
import os

today=date.today()
CHANGELOG_FILE='Changelog-386.txt'
MSG="""##  ion Asus Merlin changelog  ##\n"""
TAGGED_RELEASE_ENV_NAME='CIRCLE_TAG'


def markdown_changes(lines):
    formatted = []
    current_item = None

    for line in lines:
        if not line.strip():
            if formatted and formatted[-1] != '':
                formatted.append('')
            current_item = None
            continue

        bullet = re.match(r'^(\s*)-\s+(.*)$', line)
        if bullet:
            indent = len(bullet.group(1))
            level = 0 if indent <= 2 else 1
            formatted.append('  ' * level + '- ' + bullet.group(2).strip())
            current_item = len(formatted) - 1
        elif current_item is not None:
            formatted[current_item] += ' ' + line.strip()
        else:
            formatted.append(line.strip())

    return formatted

latest_release = None
latest_changes = list()

parser = argparse.ArgumentParser()
parser.add_argument('--markdown', action='store_true')
args = parser.parse_args()

with open(CHANGELOG_FILE) as f:
    
    rx = re.compile(r'^(\d[^()]+)\s.*$')

    for line in f:
        release_search = rx.search(line)

        if release_search:
            if latest_release:
                break
            else:
                latest_release = os.getenv(TAGGED_RELEASE_ENV_NAME, release_search.group(1))
        else:
            if latest_release:
                latest_changes.append(line)
    
    if args.markdown:
        print('##  ion release asuswrt merlin changelog  ##\n')
        print('**Date:** %s  ' % today.strftime("%B %d, %Y"))
        print('**Release:** %s\n' % latest_release)
        print('\n'.join(markdown_changes(latest_changes)))
    else:
        print(MSG)
        print('Date: %s' % today.strftime("%B %d, %Y"))
        print('Release: %s\n' % latest_release)
        print("".join(latest_changes))
