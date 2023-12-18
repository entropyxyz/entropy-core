#/bin/bash
set -eux

script_parent_path=$( cd "$(dirname "${BASH_SOURCE[0]}")" ; pwd -P )
header_file_path="$script_parent_path/../.maintain/AGPL-3.0-header.txt"

# We need to first make sure that we add a new line after the header, and then make sure that we
# print the header before the old "first line" of the file (with `N`).
#
# NOTE: This sometimes removes the last line of a file and I'm not sure why. So double check before
# committing any changes.
fd . -e rs -x sed -i '' -e "1r $header_file_path" -e "1s|^|\n|" -e "N"
