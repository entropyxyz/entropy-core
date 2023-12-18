#/bin/bash
set -eux

script_parent_path=$( cd "$(dirname "${BASH_SOURCE[0]}")" ; pwd -P )
header_file_path="$script_parent_path/../.maintain/AGPL-3.0-header.txt"

fd . -e rs -x sed -i '' -e "1r $header_file_path" -e "1s|^|\n|" -e "N"
