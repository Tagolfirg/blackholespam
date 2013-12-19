#!/usr/bin/perl

# Eat an email, get word count, check against stats, integrate into
# word count DB.
#
# Chris Kennedy, Copyright (C) 2002 The Groovy Organization
# Email: <getdown@groovy.org>

#use AnyDBM_File;
use GDBM_File;

$debug = 0;

($db, $email, $debug) = @ARGV;

if($email eq '' || $db eq '') {
  printf("Usage: $0 data_base email_file [debug]\n");
  exit 1;
}

# Open email and parse its words
chomp($email);
open(EMAIL, "$email");
@body = <EMAIL>; ## Read Email Message Into an Array.
close(EMAIL);

  $eat_headers = 0;
  $header = 0;
  $bounce = 0;
  $inside = 0;
  foreach $line (@body) {
    chomp ($line);

    if(($line =~ /^Content-Type: / && $line !~ /^Content-Type: text/) ||
      $line =~ /^Content-Transfer-Encoding: base64/ || 
      $line =~ /^[^\s\t]{,70}/) {
        $inside = 0;
    }

    if($inside == 1 && ($header == 1 || $eat_headers == 1)) {
      @words = split(/[^A-Za-z0-9\-\'\$]/, $line);
    }

    foreach $word (@words) {
      $word = lc $word;
      if($word ne ' ' && length($word) > 1 && $word !~ /^[0-9]+$/) {
        if($wordhash{$word} eq '') {
          $wordhash{$word} = 1;
        } else {
          $wordhash{$word} = $wordhash{$word}++;
        }
      }
    }

    # Control when to get data
    if ($bounce == 0 &&
      $line =~ /^\-\-\-\sBelow\sthis\sline\sis\sthe\soriginal\sbounce\.$/) {
        $bounce = 1;
    } elsif ($inside == 0 &&
      $line =~ /^\-\-\-\sBelow\sthis\sline\sis\sa\scopy\sof\sthe\smessage\.$/) {
        $inside = 1;
    } elsif ($line =~ /^\<\w+\@\w+\.\w+\>:$/ && $bounce == 1) {
      $mark = 1;
      if($show_headers == 1) {
        print "$line\n";
      }
    } elsif ($header == 0 && $line =~ /^$/ && ($inside == 1 || $failures_mode == 0)) {
      $header = 1;
      $inside = 1;
    }

  }


# Open New
dbmopen(%DB, "$db", 0664);

# get into a hash, use the values to score it.
@final = sort {$wordhash{$b} <=> $wordhash{$a}} keys %wordhash;
$rate = 1;
$rate_minus = 1;
$rate_total = 0;

for($i=0;$final[$i] && $i < 15;$i++) {
  $rate_total += $DB{$final[$i]};
  if($debug == 1) {
    printf("$i) word: $final[$i] score: $DB{$final[$i]} total: $rate_total\n");
  }
  $rate = $rate * $DB{$final[$i]};
  $rate_minus = $rate_minus * (1.0 - $DB{$final[$i]});
}

my $prob = $rate / ($rate + $rate_minus);

if ($prob > 0.80) {
  printf("Spam score of $prob\n");
  dbmclose(%DB);

  # Is Spam
  exit 69;
}

# Close Bad DB
dbmclose(%DB);

# Not Spam
exit 0;


# Section to Add email to DB


# Add word
if($DB{$word} eq '') {
  $DB{$word} = 0.0;
} else {
  $DB{$word}++;
}

# Incriment
$DB{"total.email"}++;


