#!/usr/bin/perl

# Build DB files with parsed email stats
#
# Chris Kennedy, Copyright (C) 2000 The Groovy Organization
# Email: <getdown@groovy.org>

#use AnyDBM_File;
use GDBM_File;

$DBfile = ".stats";

$show_headers = 0;
$debug = 0;
$i = 0;
%wordhash;

$failures_mode = 0;
$eat_headers = 0;

if($ARGV[0] eq '-h' || $ARGV[0] eq '') {
  printf("Usage: $0 location failures_mode show_headers eat_headers debug\n");
  printf("\tlocation [dir]: is a directory of email to parse.\n");
  printf("\tfailures_mode [0/1]: if your parsing double bounce messages.\n");
  printf("\tshow_headers  [0/1]: show email headers too.\n");
  printf("\teat_headers   [0/1]: use the email headers in stats\n");
  printf("\tdebug         [0/1]: debug level, -1 is good\n");
  exit 0;
}

($location, $failures_mode, $show_headers, $eat_headers, $debug) = @ARGV;
if ($ARGV[0] eq '' || ! -d "$location/") {
  $location = "/export/home/f/failures/mail/new";
  print "Using Default Location of $location\n\n";
}

## Get the list of email files and form an Array.
opendir (NEW, "$location/");
@listing = grep !/^\.\.?$/, readdir NEW;
closedir (NEW);

foreach $email (@listing) {
  my $inside = 0;
  my $header = 0;
  $i++;
  chomp ($email);
  open (EMAIL, "$location/$email");
  @body = <EMAIL>; ## Read Email Message Into an Array.
  close (EMAIL);

  $bounce = 0;
  $inside = 0;
  foreach $line (@body) {
    if($debug > 1) {
      printf("$line");
    }
    chomp ($line);

    if(($line =~ /^Content-Type: / && $line !~ /^Content-Type: text/) ||
      $line =~ /^Content-Transfer-Encoding: base64/ || 
      $line =~ /^[^\s\t]{,70}/) {
        $inside = 0;
    }

    if($inside == 1 && ($header == 1 || $eat_headers == 1)) {
      #$line =~ s/^.*: //g;
      #$line =~ s/\t+/ /g;
      #$line =~ s/\s+/ /g;
      #$line =~ s/\n$/ /g;

      @words = split(/[^A-Za-z0-9\-\'\$]/, $line);
    }

    foreach $word (@words) {
      $word = lc $word;
      if($word ne ' ' && length($word) > 1 && $word !~ /^[0-9]+$/) {
        if($debug >= 1 ) {
          printf("$word\n");
        }

        if($wordhash{$word} eq '') {
          $wordhash{$word} = 1;
        } else {
          $wordhash{$word} = $wordhash{$word}++;
        }
      }
    }

    if ($bounce == 1 || $failures_mode == 0) {
      if ($line =~ /^Received:\sfrom\s/) {
        $found = 1;
        if($show_headers == 1) {
          print "$line\n";
        }
      } elsif ($found == 1 && $line =~ /^$/) {
        if($show_headers == 1) {
          print "$line\n";
        }
        $found = 0;
      } elsif ($found == 1) {
        if($show_headers == 1) {
          print "$line\n";
        }
      } elsif ($found == 0 &&
               $line !~ /^Subject:\sfailure\snotice$/ &&
              ($line =~ /^Subject:\s/ ||
               $line =~ /^SUBJECT:\s/))
      {
        if($show_headers == 1) {
          print "$line\n";
        }
      }
    }
 
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
  if ($mark == 1 && $show_headers == 1) {
    print "--\n";
  }
  $mark = 0; $found = 0;
}

dbmopen(%DB, "$DBfile", 0664);
if($DB{"total.email"} eq '') {
  $DB{"total.email"} = "$i";
} else {
  $DB{"total.email"} = $DB{"total.email"} + $i;
}
while (($key, $value) = each %wordhash) {
  $score = ($value / $i);
  push @totals, "$key $value $score";
 
  # DBM File
  if($DB{$key} eq '') {
    $DB{$key} = "$value";
  } else {
    $DB{$key} = $DB{$key} + $value;
  }
  if($debug == 0) {
    printf("%-25s %d %.2f\n", $key, $value, $score);
  }
}
dbmclose(%DB);

@totals2 = @totals;
sub bynum {
  ($aa, $ab, $ac) = split(/ /, $a);
  ($ba, $bb, $cc) = split(/ /, $b);
  $bb <=> $ab;
}
@totals = sort bynum @totals2;

$counter = 0;
foreach $line (@totals) {
  $counter++;
  if($counter > 40) {
    break;
  }
  ($key, $value, $score) = split(/ /, $line);
  printf("%-25s %d %.2f\n", $key, $value, $score);
}

printf("Total Email $i\n");

