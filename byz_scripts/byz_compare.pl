#!/usr/bin/perl

# Compare results in two db files, write to a third.
#
# Chris Kennedy, Copyright (C) 2002 The Groovy Organization
# Email: <getdown@groovy.org>

#use AnyDBM_File;
use GDBM_File;

$debug = -1;

($goodDB, $badDB, $newDB) = @ARGV;

if($newDB eq '') {
  printf("Usage: $0 goodDB badDB newDB\n");
  printf("\tThe newDB file is removed if existing, and recreated\n");
  printf("\twith the new stats in it for the good and bad DB files.\n");
  exit 1;
}

$goodTotal = 0;
$badTotal = 0;

# Remove old combo DB
if( -f "$newDB" && ! -l "$newDB") {
  unlink($newDB);
}

# Open New
dbmopen(%DBnew, "$newDB", 0664);
$DBbad{"total.email"} = 0;

# Open Bad
dbmopen(%DBbad, "$badDB", 0664);
$badTotal = $DBbad{"total.email"};

# Open Good
dbmopen(%DBgood, "$goodDB", 0664);
$goodTotal = $DBgood{"total.email"};

while (($key, $value) = each %DBgood) {
  my $diff = 0.0;
  $value = 2 * $value;
  if(($value + $DBbad{$key}) <= 5) {
    next;
  }
 
  # Bad DBM File
  if($DBbad{$key} eq '' || $DBbad{$key} == 0) {
    if($DBgood{$key} eq '' || $DBgood{$key} == 0) {
      $scoreBad = 0.00;
      $scoreGood = 0.00;
      $diff = 0.20;
    } else {
      $scoreBad = 0.00;
      $scoreGood = ($value / $goodTotal);
    }
  } else {
    if($DBgood{$key} eq '' || $DBgood{$key} == 0) {
      $scoreGood = 0.00;
      $scoreBad = ($DBbad{$key} / $badTotal);
    } else {
      $scoreGood = ($value / $goodTotal);
      $scoreBad = ($DBbad{$key} / $badTotal);
    }
  }
  if($diff == 0.0) {
    if($scoreBad > 1.00) {
      $scoreBad = 1.00;
    } 
    if($scoreGood > 1.00) {
      $scoreGood = 1.00;
    } 
    $diff = $scoreBad / ($scoreGood + $scoreBad);
  }
  if($diff < 0.01) {
    $diff = 0.01;
  } elsif($diff > 0.99) {
    $diff = 0.99;
  }
  push @totals, "$key $value $DBbad{$key} $scoreGood $scoreBad $diff";
  $DBnew{$key} = "$diff";
  $DBnew{"total.email"}++;

  if($debug == 1) {
    printf("%-25s %8d %8d %.2f %.2f [%.2f]\n", 
         $key, $value, $DBbad{$key}, $scoreGood, $scoreBad, $diff);
  }
}

# Close Good
dbmclose(%DBgood);

# Close Bad
dbmclose(%DBbad);

# Close Bad
dbmclose(%DBnew);

if(debug < 1) {
  $total = $badTotal + $goodTotal;
  printf("Total Good Email $goodTotal\n");
  printf("Total Bad Email $badTotal\n");
  printf("Total Email $total\n");
  exit 0;
}
@totals2 = @totals;
sub bynum {
  ($aa, $ab, $ac, $ad, $ae, $af) = split(/ /, $a);
  ($ba, $bb, $cc, $bd, $be, $bf) = split(/ /, $b);
  $bf <=> $af;
}
@totals = sort bynum @totals2;

$counter = 0;
foreach $line (@totals) {
  $counter++;
  if($counter > 40) {
    break;
  }
  ($key, $value, $badvalue, $scoreGood, $scoreBad, $diff) = split(/ /, $line);
  printf("%-25s %8d %8d %5.2f %5.2f %5.2f\n", 
       $key, $value, $badvalue, $scoreGood, $scoreBad, $diff);
}

$total = $badTotal + $goodTotal;
printf("Total Good Email $goodTotal\n");
printf("Total Bad Email $badTotal\n");
printf("Total Email $total\n");

exit 0;
