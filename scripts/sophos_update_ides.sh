#!/bin/sh
#
# Automatically fetch and apply Sweep IDE updates from Sophos
# This script was modified from the one included with 
#    Copyright (c) 2001 Leon Brooks <sophosticated@cyberknights.com.au>
# There is no warranty of any kind. You may use these scripts only as allowed
# under the terms of the GNU GPL (see http://www.gnu.org/copyleft/gpl.html for
# details).
#
#
VIRUS_EMAIL=root
ADMIN_EMAIL=
SOPHOS_PATH=/opt/sophos
SOPHOS_VERSION=$(
  ${SOPHOS_PATH}/bin/sweep -v |
  gawk '/^Product version / { print gensub("\\.","","",$4) }' |
  sed -e s/[^0-9]//g
)
# 
cd ${SOPHOS_PATH}/tmp
#
#
rm -f ${SOPHOS_VERSION}_ides.zip wget_results.temp.txt
if ! wget -q \
  http://www.sophos.com/downloads/ide/${SOPHOS_VERSION}_ides.zip \
  &> wget_results.temp.txt; then
        mail -s 'Failed to fetch Sophos updates, wget error text enclosed' \
          $VIRUS_EMAIL$ADMIN_EMAIL < wget_results.temp.txt &> /dev/null
        logger -t sophos "Wget error on IDE update ($SOPHOS_VERSION)"
        exit 1
fi
#
cd ${SOPHOS_PATH}/sav
if unzip -ou ${SOPHOS_PATH}/tmp/${SOPHOS_VERSION}_ides \
  &> ${SOPHOS_PATH}/tmp/unzip_results.temp.txt; then
        NUM=`wc -l ${SOPHOS_PATH}/tmp/unzip_results.temp.txt|gawk '{print $1}'`
        if [ $NUM -gt 1 ]; then
          grep -v ^Archive: <${SOPHOS_PATH}/tmp/unzip_results.temp.txt | \
          mail -s 'The enclosed Sophos virus IDE tags were added' \
            $VIRUS_EMAIL$ADMIN_EMAIL &> /dev/null
          logger -t sophos $[
            $(wc -l ${SOPHOS_PATH}/tmp/unzip_results.temp.txt | \
            gawk '{ print $1 }') - 1
              ] virus IDEs added "(to $SOPHOS_VERSION)"
          exit 0
        fi
else
        mail -s 'Unpacking of Sophos virus IDE tags failed, error enclosed' \
          $VIRUS_EMAIL$ADMIN_EMAIL < ${SOPHOS_PATH}/tmp/unzip_results.temp.txt &> /dev/null
        logger -t sophos "Unzip error on IDE update ($SOPHOS_VERSION)"
        exit 2
fi
cd ${SOPHOS_PATH}/tmp
rm -f unzip_results.temp.txt wget_results.temp.txt

