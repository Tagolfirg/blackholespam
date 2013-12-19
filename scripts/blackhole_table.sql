# Warning, add passwords, here and in blackhole.h
insert into user values('localhost','blackhole',password(''),'N','N','N','N','N','N','N','N','N','N','N','N','N','N');

insert into db values('localhost','BlackHole','blackhole','Y','Y','Y','Y','Y','Y','N','Y','Y','Y');


FLUSH PRIVILEGES;

# username 
# domain
# timestamp 
#
# level 
# maxscore
# one_box
# spam_header
# virus_header
# nosignature
# expire
# rbl_check 
# bounce 
# white_list
# sdelete
# vdelete
# maxbytes
# maxbytes_trunc
# sscan
# vscan 
# valert 
# virus_bcc_to
# vclean 
# check_dns 
# body_check_spam 
# body_check_porn 
# body_check_racist 
# body_check
#
# bounce_msg 
# rbl_hosts 
# my_relay 
# excluded_relay
# my_email 
# bad_email 
# good_email 
# bad_rcptto
# good_rcptto
# good_relay 
# bad_relay 
# bad_subject
# bad_headers
# charsets
# my_body 
# ascii_128
# check_reverse
# strict_reverse
# no_spam_check
# no_virus_check
# bad_ctype
# bad_encoding
# smtp_relay
# spam_fwd
# virus_fwd
# ok_fwd
# sreport
# exec_prog
# bad_attachment
# bad_subject_action
# bad_email_action
# bad_relay_action
# rbl_check_action
# body_check_spam_action
# body_check_porn_action
# body_check_racist_action
# white_list_action
# my_email_action
# check_dns_action
# body_check_action
# charsets_action
# ascii_128_action
# check_reverse_action
# razor_action
# bad_headers_action
# bad_attachment_action


use BlackHole;
drop table BlackHole;
create table BlackHole (username VARCHAR(25) NOT NULL, 
			domain VARCHAR(25) NOT NULL,
			timestamp INT DEFAULT 0,
			level TINYINT DEFAULT 0,
			nosignature TINYINT DEFAULT 0,
			maxscore TINYINT DEFAULT 0,
			expire TINYINT DEFAULT 0,
			one_box TINYINT DEFAULT 0,
			rbl_check TINYINT DEFAULT 1,
			bounce TINYINT DEFAULT 1,
			white_list TINYINT DEFAULT 0,
			sdelete TINYINT DEFAULT 0,
			vdelete TINYINT DEFAULT 0,
			maxbytes INT DEFAULT 0,
			maxbytes_trunc TINYINT DEFAULT 0,
			sscan TINYINT DEFAULT 1,
			vscan TINYINT DEFAULT 0,
			valert TINYINT DEFAULT 1,
			virus_bcc_to VARCHAR(255) DEFAULT NULL,
			vclean TINYINT DEFAULT 1,
			check_dns TINYINT DEFAULT 0,
			exec_prog TINYINT DEFAULT 0,
			sreport TINYINT DEFAULT 0,
			check_reverse TINYINT DEFAULT 0,
			strict_reverse TINYINT DEFAULT 0,
			body_check SMALLINT DEFAULT 0,
			body_check_spam SMALLINT DEFAULT 0,
			body_check_porn SMALLINT DEFAULT 0,
			body_check_racist SMALLINT DEFAULT 0,
			bounce_msg VARCHAR(255) DEFAULT NULL,
			smtp_relay VARCHAR(255) DEFAULT NULL,
			spam_fwd VARCHAR(255) DEFAULT NULL,
			virus_fwd VARCHAR(255) DEFAULT NULL,
			ok_fwd VARCHAR(255) DEFAULT NULL,
			rbl_hosts MEDIUMTEXT DEFAULT NULL,
			my_relay MEDIUMTEXT DEFAULT NULL,
			excluded_relay MEDIUMTEXT DEFAULT NULL,
			my_email MEDIUMTEXT DEFAULT NULL,
			bad_email MEDIUMTEXT DEFAULT NULL,
			good_email MEDIUMTEXT DEFAULT NULL,
			good_relay MEDIUMTEXT DEFAULT NULL,
			bad_relay MEDIUMTEXT DEFAULT NULL,
			good_rcptto MEDIUMTEXT DEFAULT NULL,
			bad_rcptto MEDIUMTEXT DEFAULT NULL,
			bad_subject MEDIUMTEXT DEFAULT NULL,
			bad_headers MEDIUMTEXT DEFAULT NULL,
			charsets MEDIUMTEXT DEFAULT NULL,
			no_virus_check MEDIUMTEXT DEFAULT NULL,
			no_spam_check MEDIUMTEXT DEFAULT NULL,
			bad_ctype MEDIUMTEXT DEFAULT NULL,
			bad_encoding MEDIUMTEXT DEFAULT NULL,
			bad_attachment MEDIUMTEXT DEFAULT NULL,
			bad_attachment_action MEDIUMTEXT DEFAULT NULL,
			bad_subject_action MEDIUMTEXT DEFAULT NULL,
			bad_email_action MEDIUMTEXT DEFAULT NULL,
			bad_relay_action MEDIUMTEXT DEFAULT NULL,
			rbl_check_action MEDIUMTEXT DEFAULT NULL,
			body_check_spam_action MEDIUMTEXT DEFAULT NULL,
			body_check_porn_action MEDIUMTEXT DEFAULT NULL,
			body_check_racist_action MEDIUMTEXT DEFAULT NULL,
			white_list_action MEDIUMTEXT DEFAULT NULL,
			my_email_action MEDIUMTEXT DEFAULT NULL,
			check_dns_action MEDIUMTEXT DEFAULT NULL,
			body_check_action MEDIUMTEXT DEFAULT NULL,
			charsets_action MEDIUMTEXT DEFAULT NULL,
			ascii_128_action MEDIUMTEXT DEFAULT NULL,
			check_reverse_action MEDIUMTEXT DEFAULT NULL,
			razor_action MEDIUMTEXT DEFAULT NULL,
			bad_headers_action MEDIUMTEXT DEFAULT NULL,
			ascii_128 TINYINT DEFAULT 0,
			razor TINYINT DEFAULT 0,
			my_body MEDIUMTEXT DEFAULT NULL,
			spam_header MEDIUMTEXT DEFAULT NULL,
			virus_header MEDIUMTEXT DEFAULT NULL,
			INDEX BlackHole_I (username,domain),
			PRIMARY KEY(username,domain)
);

#timestamp, username, domain, entry
drop table log;
create table log (timestamp TIMESTAMP(0), 
			username VARCHAR(25) NOT NULL,
			domain VARCHAR(25) NOT NULL,
			hostname VARCHAR(255) DEFAULT NULL,
			status VARCHAR(50) DEFAULT NULL,
			score FLOAT DEFAULT NULL,
			size BIGINT(20) DEFAULT NULL,
			relay VARCHAR(255) DEFAULT NULL,
			sender VARCHAR(255) DEFAULT NULL,
			recipient VARCHAR(255) DEFAULT NULL,
			INDEX log_I (timestamp,username,domain)
);

