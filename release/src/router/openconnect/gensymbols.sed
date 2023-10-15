#
# Usage: sed -Enf gensymbols.sed openconnect.h | sed -nf- libopenconnect.map.in
#
# This sed script is used to process openconnect.h and emit another
# sed script, which is used to process libopenconnect.map.in.
#
# The ultimate goal is to generate a libopenconnect5.symbols file in
# the form consumed by dpkg-gensymbols, which has a list of symbols
# (including their @OPENCONNECT_5_x version) along with the first
# version of the *package* in which they appear.
#
# For each symbol version tag (e.g. OPENCONNECT_5.8) we want to emit a
# line for the tag itself with the corresponding OpenConnect version:
#
#  OPENCONNECT_5_8@OPENCONNECT_5_8 9.00
#
# Since the symbol versions are given in reverse order in openconnect.h,
# the script we generate will *prepend* the line for each symbol version
# to the hold space as it goes through on line 1 (of libopenconnect.map.in)
# and then print it all out (in the correct order, with the overall file
# header line prepended too) at the end.
#
# And then for each symbol between the 'OPENCONNECT_5_8 {' and closing '}'
# in libopenconnect.map.in it then emits that symbol name suffixed with
# the @OPENCONNECT_5_8 API version and the OpenConnect version:
#
# openconnect_set_external_browser_callback@OPENCONNECT_5_8 9.00
# openconnect_set_mca_cert@OPENCONNECT_5_8 9.00
# openconnect_set_mca_key_password@OPENCONNECT_5_8 9.00
# openconnect_set_sni@OPENCONNECT_5_8 9.00
# openconnect_set_useragent@OPENCONNECT_5_8 9.00
#
# There is a slight complication in that OPENCONNECT_5.0 symbol version
# doesn't follow the convention of using _ instead of . between major
# and minor numbers, fixed up at the start by only doing the . → _
# substitution for 5.[1-9]* and not 5.0.


# First change . to _ for all but 5.0.

s/API version 5.([1-9])/API version 5_\1/

# Now, for each API version...

s/^ \* API version (5[._][0-9.]+) \(v([0-9.]+); 20.*/\
# Swap hold and pattern space, prepend newline and OPENCONNECT_\1, swap back \
1{x;s\/\(.*\)\/\\\
 OPENCONNECT_\1@OPENCONNECT_\1 \2\\1\/;x;\}\
# Match actual symbols within the OPENCONNECT_\1 \{ ... \} range and print them with versions \
\/^OPENCONNECT_\1\/,\/^\}\/s\/^\\t(openconnect_.*);\/ \\1@OPENCONNECT_\1 \2\/p\
/p

# At the end of processing openconnect.h, therefore at the end
# of sed script we're generating, tell it to swap hold and pattern
# spare one last time, prepend the header for the .symbol file,
# then print it.
${s/.*//;a\
1{x;s\/\(.*\)\/libopenconnect.so.5 libopenconnect5 #MINVER#\\1\/p\
}
p;}
