#!/system/bin/sh
MODDIR=${0%/*}
rm "$MODDIR/postFsData.log"
echo "Init" >> "$MODDIR/postFsData.log"

LIBPATH="/vendor/lib"
LIB="$LIBPATH/libexynoscamera3.so"
REGEX="^(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) (([[:digit:]]| )[[:digit:]]) ([[:digit:]][[:digit:]][[:digit:]][[:digit:]])$"

timestamp_from_lib () {
        echo "timestamp_from_lib" >> "$MODDIR/postFsData.log"

        lib_date=$(strings $LIB | grep -o -E "$REGEX") # Expected output format is "May 29 2021"
        if test -z "$lib_date"; then
                echo "No regex match!" >> "$MODDIR/postFsData.log"
                timestamp=-1
                return
        fi

        echo "Match: $lib_date" >> "$MODDIR/postFsData.log"

        year=${lib_date: -4}
        month=${lib_date:0:3}
        day=${lib_date:4:2}
        day="${day/ /0}"

        if [ "$month" = "Jan" ]; then
                month="01"
        elif [ "$month" = "Feb" ]; then
                month="02"
        elif [ "$month" = "Mar" ]; then
                month="03"
        elif [ "$month" = "Apr" ]; then
                month="04"
        elif [ "$month" = "May" ]; then
                month="05"
        elif [ "$month" = "Jun" ]; then
                month="06"
        elif [ "$month" = "Jul" ]; then
                month="07"
        elif [ "$month" = "Aug" ]; then
                month="08"
        elif [ "$month" = "Sep" ]; then
                month="09"
        elif [ "$month" = "Oct" ]; then
                month="10"
        elif [ "$month" = "Nov" ]; then
                month="11"
        elif [ "$month" = "Dec" ]; then
                month="12"
        fi

        echo "Lib date to timestamp" >> "$MODDIR/postFsData.log"
        timestamp=$(date -d $year-$month-$day +%s)
}

timestamp_from_vendor_build_date () {
        echo "timestamp_from_vendor_build_date" >> "$MODDIR/postFsData.log"
        
        timestamp=$(getprop ro.vendor.build.date.utc) || timestamp=-1
        if test -z "$timestamp"; then
                echo "Empty timestamp!" >> "$MODDIR/postFsData.log"
                timestamp=-1
        fi
}

timestamp_from_lib
if [[ "$timestamp" == -1 ]]; then
        timestamp_from_vendor_build_date
fi

echo "Timestamp: $timestamp" >> "$MODDIR/postFsData.log"

destination="$MODDIR/system$LIB"
mkdir -p "$MODDIR/system$LIBPATH"

if [ "$timestamp" -gt 1630458000 ]; then # September 1, 2021
        selected_lib="$MODDIR/cameraLibs/libexynoscamera3_oct15.so"
else
        selected_lib="$MODDIR/cameraLibs/libexynoscamera3_apr17.so"
fi

echo "$selected_lib --> $destination" >> "$MODDIR/postFsData.log"
cp "$selected_lib" "$destination"