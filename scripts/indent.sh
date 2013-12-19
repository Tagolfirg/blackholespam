#!/bin/sh
#
# Chris Kennedys way of indenting, probably ugly to all else
#

if [ "$1" = "" ]; then
  echo "Enter some files to Indent please..."
  exit
fi

indent -nut -nprs -npcs -i2 -br -bli0 -nsaw -nsai -nsaf -npsl -ce -cli0 -l80 -lc80 $@

# The End
