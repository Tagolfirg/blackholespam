Black Hole Spam/Virus Filter for Qmail, Postfix, Sendmail, Exim and Courier.
============================================================================

Please check the website for the main documentation...

 Main Online Docs: http://www.groovy.org/source/docs/blackhole/

 Main Site:        http://www.groovy.org/blackhole.shtml

Mailing List:
 http://lists.sourceforge.net/lists/listinfo/blackholespam-general

Directorys...
 ./report_programs	Where contributed reporting programs are.
 ./scripts		general mysql/configure type programs

Quick local view of Documentation using lynx or w3m text browsers...

 w3m  -dump groovy.org/source/docs/blackhole/index_a.shtml | more
 lynx -dump groovy.org/source/docs/blackhole/index_a.shtml | more

Note: Please post the system used, the smtp server used, the output of
      blackhole -I, and your .blackhole/blackhole.conf files when having
      errors and wanting the fix to be as quick as possible.  Also using
      the --enable-debug option to configure will help too, when running
      test messages through blackhole, the output of that helps too.

Example: (after using ,/configure --enable-debug)
 uname -a ; ./blackhole -I ; cat ~/.blackhole ; cat test_msg_spam|./blackhole -d

---
Chris Kennedy 
URL: http://the.groovy.org/
EMAIL: getdown (a+) groovy.org
