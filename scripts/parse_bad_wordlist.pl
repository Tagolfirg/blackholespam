#!/usr/bin/perl
($file,$SCORE) = @ARGV;

if($file eq '') {
  $file = "bad_word_list";
}
if($SCORE eq '') {
  $SCORE = 1.0;
}

if($file =~ /^\-/ || ! -f "$file") {
  printf("Usage: %s [file] [score]\n", $0);
  exit 1;
}

if(!open(LIST,"$file")) {
  printf("Error opening %s\n", $file);
  exit 1;
}

while(<LIST>) {
  if($_ =~ /^\#/ || $_ =~ /^\/\// || $_ =~ /^\*/ || $_ =~ /^\s/) {
    next;
  }
  $_ =~ s/\n//g;
  printf("\t{ \"(?i)\\\\b%s\\\\b\", %.1f },\n", $_, $SCORE);
}

close(LIST);
