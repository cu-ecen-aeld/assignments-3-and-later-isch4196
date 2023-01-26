#!/bin/sh

set -e

#check args exist
if [ -z $1 ] || [ -z $2 ]
then
    echo "Two arguments expected"
    exit 1
fi

writefile=$1
writestr=$2

#parse for directory, file
directory=$(echo $writefile | rev | cut -d "/" -f2- | rev)
filename=$(echo $writefile | rev | cut -d "/" -f1 | rev)

if [ "$writefile" = "$directory" ]; then
    filename=$directory
    fullpath=$filename
    touch $filename || exit 1
else
    mkdir -p $directory || exit 1
    fullpath=$directory"/"$filename
    touch $fullpath || exit 1
fi

echo $writestr > $fullpath
