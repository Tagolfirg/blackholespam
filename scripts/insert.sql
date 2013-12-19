
insert into BlackHole set username='USERNAME',domain='default';

update BlackHole set \
	timestamp=UNIX_TIMESTAMP(), \
	level=20, \
	my_relay='', \
	my_email='', \
	bad_subject='', \
	good_email='', \
	bad_email='', \
	good_relay='', \
	bad_relay='', \
	rbl_check=1, \
	check_dns=-1, \
	white_list=-1, \
	body_check_spam=-1, \
	body_check_porn=-1, \
	body_check_racist=-1, \
	body_check=-1, \
	vscan=-1, \
	vclean=-1, \
	valert=-1, \
	bounce=-1, \
	bounce_msg='', \
        charsets='', \
        ascii_128=-1, \
        my_body='', \
  where username='USERNAME' and domain='default';
	
	
