#!/usr/bin/perl

($DIR) = @ARGV;

my $DEBUG = 0;
my $sub_file = $DIR . "20_body_tests.cf";
my $val_file = $DIR . "50_scores.cf";

if($DIR =~ /^\-/ || $DIR !~ /\/$/ 
	|| (! -d "$DIR" && ! -f "$sub_file" && ! -f $val_file)) 
{
  printf("Usage: %s [dir of spam-assassin]\n", $0);
  printf("\n\tinfo - you want to use <dir of spam assassin/rules/>\n");
  exit 1;
}

my %master_hash;

if(!open(SUB_FILE,"$sub_file")) {
  printf("Error opening %s\n", $sub_file);
  exit 1;
}

while(<SUB_FILE>) {
  if($_ =~ /^\#/ || $_ =~ /^\s/) { next };
  my $full_value = '';

  $_ =~ s/\s+/ /g;
  $_ =~ s/\t+/ /g;
  if($DEBUG) {
    printf("Breaking up: %s\n", $_);
  }
  my ($field,$main,@values) = split(/\s+/, $_);

  if($DEBUG) {
    printf("Entering: %s, %s\n", $field, $main);
    printf(" Value: ");
  }
  for($i=0;$values[$i];$i++) {
    $full_value.= "$values[$i] ";
    if($DEBUG) {
      printf("%s", $values[$i]);
    }
  }
  if($DEBUG) {
    printf("\n");
  }
  $full_value =~ s/\s+$//g;
  $master_hash{$main}{$field} = $full_value;
   
}

close(SUB_FILE);

if(!open(VAL_FILE,"$val_file")) {
  printf("Error opening %s\n", $val_file);
  exit 1;
}

while(<VAL_FILE>) {
  if($_ =~ /^\#/ || $_ =~ /^\s/) { next };
  my $full_value = '';

  $_ =~ s/\s+/ /g;
  $_ =~ s/\t+/ /g;
  if($DEBUG) {
    printf("Breaking up: %s\n", $_);
  }
  my ($field,$main,@values) = split(/\s+/, $_);
  
  if($DEBUG) {
    printf("Entering: %s, %s\n", $field, $main);
    printf(" Value: ");
  }
  for($i=0;$values[$i];$i++) {
    $full_value.= "$values[$i] ";
    if($DEBUG) {
      printf("%s", $values[$i]);
    }
  }
  if($DEBUG) {
    printf("\n");
  }
  $full_value =~ s/\s+$//g;
  $full_value =~ s/^\s+//g;
  $master_hash{$main}{$field} = $full_value;

}

close(VAL_FILE);

foreach $record (sort keys %master_hash) {
  if($master_hash{$record}{'score'} ne '' 
	&& ($master_hash{$record}{'body'} ne '' 
		|| $master_hash{$record}{'rawbody'} ne '')) 
  {
    printf("\t/* %s %s */\n", $record, $master_hash{$record}{'describe'});
    if($master_hash{$record}{'body'} ne '') {
      $master_hash{$record}{'body'} =~ s/^\///g;
      $master_hash{$record}{'body'} =~ s/\/$//g;
      $master_hash{$record}{'body'} =~ s/\\\//\//g;
      $master_hash{$record}{'body'} =~ s/\\/\\\\/g;
      $master_hash{$record}{'body'} =~ s/\"/\\"/g;
      $master_hash{$record}{'body'} =~ s/\'/\\'/g;
      $master_hash{$record}{'body'} =~ s/\\\\\\\'/\\\'/g;
      $master_hash{$record}{'body'} =~ s/\\\\\\\"/\\\"/g;
      $master_hash{$record}{'body'} =~ s/\\\\\'/\\\'/g;
      $master_hash{$record}{'body'} =~ s/\\\\\"/\\\"/g;
      if($master_hash{$record}{'body'} =~ /\/([imsx]{0,4})$/) {
	my $flags = $1;
	$master_hash{$record}{'body'} =~ s/\/$flags$//g;
	$master_hash{$record}{'body'} =~ s/^/\(?$flags\)/g;
      }
      printf("\t{ \"%s\", ", $master_hash{$record}{'body'});
    }
    if($master_hash{$record}{'rawbody'} ne '') {
      $master_hash{$record}{'rawbody'} =~ s/^\///g;
      $master_hash{$record}{'rawbody'} =~ s/\/$//g;
      $master_hash{$record}{'rawbody'} =~ s/\\\//\//g;
      $master_hash{$record}{'rawbody'} =~ s/\\/\\\\/g;
      $master_hash{$record}{'rawbody'} =~ s/\"/\\"/g;
      $master_hash{$record}{'rawbody'} =~ s/\'/\\'/g;
      $master_hash{$record}{'rawbody'} =~ s/\\\\\\\'/\\\'/g;
      $master_hash{$record}{'rawbody'} =~ s/\\\\\\\"/\\\"/g;
      $master_hash{$record}{'rawbody'} =~ s/\\\\\'/\\\'/g;
      $master_hash{$record}{'rawbody'} =~ s/\\\\\"/\\\"/g;
      if($master_hash{$record}{'rawbody'} =~ /\/([imsx]{0,4})$/) {
	my $flags = $1;
	$master_hash{$record}{'rawbody'} =~ s/\/$flags$//g;
	$master_hash{$record}{'rawbody'} =~ s/^/\(?$flags\)/g;
      }
      printf("\t{ \"%s\", ", $master_hash{$record}{'rawbody'});
    }
    printf("%s },\n", $master_hash{$record}{'score'});
  }
}

# The End
