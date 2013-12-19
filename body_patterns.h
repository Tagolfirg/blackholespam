/* body_patterns.h */
/*
   Copyright (C) 2002
        Chris Kennedy, The Groovy Organization.

   The Blackhole is free software; you can redistribute it and/or
   modify it under the terms of the GNU Library General Public License as
   published by the Free Software Foundation; either version 2 of the
   License, or (at your option) any later version.

   The Blackhole is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Library General Public License for more details.

   For a copy of the GNU Library General Public License
   write to the Free Software Foundation, Inc., 59 Temple Place - Suite 330,
   Boston, MA 02111-1307, USA.  or go to http://www.gnu.org
*/
/* These regex patterns and scores were used from the project - 
   Spam Assassin, it has the greatest method I have found to do
   this, check them out at http://www.spamassassin.org
*/
#ifndef _BODY_PATTERNS_H
#define _BODY_PATTERNS_H 1

int SPAM = 5;
int PORN = 6;
int RACIST = 7;
int MY = 11;

/* Linked Lists, for Body Matches */
struct spam_pattern
{
  char *pattern;
  float score;
}
spam_pattern[] =
{
  /* 25FREEMEGS_URL Frequent SPAM content */
  {
  "(?i)http://.*25freemegs\\.com", 1.00}
  ,
    /* ADDRESSES_ON_CD Only thing addresses on CD are useful for is SPAM */
  {
  "(?i)addresses on cd", 1.00}
  ,
    /* AMAZING Contains word 'AMAZING' */
  {
  "AMAZING", 3.46}
  ,
    /* ANOTHER_NET_AD Tells you it's an ad */
  {
  "Another Internet Ad campaign produced", 1.00}
  ,
    /* AOL_USERS_LINK Includes a link for AOL users to click */
  {
  "(?is)AOL\\s+Users\\s+Click", 0.90}
  ,
    /* ASCII_FORM_ENTRY Contains an ASCII-formatted form */
  {
  "[^<][A-Za-z][A-Za-z]+.{1,15}?\\s+_{30,}", 1.55}
  ,
    /* ASKS_BILLING_ADDRESS Asks for a billing address */
  {
  "(?i)\\bbilling address\\b", 1.00}
  ,
    /* AUTO_EMAIL_REMOVAL Claims auto-email removal */
  {
  "Auto Email Removal", 1.43}
  ,
    /* A_HREF_TO_OPT_OUT Link to a URL containing "opt-in" or "opt-out" */
  {
  "(?i)href[3D=\\s\"\']*\\S+opt(?:-in|-out|in|out)", 1.0}
  ,
    /* A_HREF_TO_REMOVE Link to a URL containing "remove" */
  {
  "(?i)href[3D=\\s\"\']*\\S+remove", 1.82}
  ,
    /* A_HREF_TO_UNSUB Link to a URL containing "unsubscribe" */
  {
  "(?i)href[3D=\\s\"\']*\\S+unsubscribe", 0.01}
  ,
    /* BALANCE_FOR_LONG Message text is over 500 lines long */
  {
  "eval:check_for_very_long_text()", -2.0}
  ,
    /* BE_AMAZED Apparently, you'll be amazed */
  {
  "(?i)\\bbe amazed\\b", 1.03}
  ,
    /* BILLION_DOLLARS Talks about lots of money */
  {
  "[BM]ILLION DOLLAR", 0.90}
  ,
    /* BILL_1618 Claims compliance with senate bill 1618 */
  {
  "(?i)Bill.{0,10}1618.{0,10}TITLE.{0,10}III", 1.15}
  ,
    /* BRAND_NEW_PAGER No such thing as a free lunch */
  {
  "BRAND NEW Pager FREE", 4.90}
  ,
    /* BUGGY_CGI Broken CGI script message */
  {
  "Below is the result of your feedback form", 3.99}
  ,
    /* BUGGY_CGI_DE Broken German CGI script message */
  {
  "(?i)Neue Mail aus dem Fitzshop Briefkasten", 4.0}
  ,
    /* BUGGY_CGI_DE_2 Broken German CGI script message (2) */
  {
  "(?i)Diese Mail wurde &uuml;bertragen von", 4.0}
  ,
    /* BUGGY_CGI_DE_3 Broken German CGI script message (3) */
  {
  "(?i)Diese Daten wurden Ihnen von Ihrem OnlineFormular", 4.0}
  ,
    /* BUGGY_CGI_ES Broken Spanish CGI script message */
  {
  "(?i)Aqui esta el resultado de su formulario", 1.0}
  ,
    /* BUGGY_CGI_PT Broken Portuguese CGI script message */
  {
  "Abaixo o resultado do preenchimento do Formulario", 4.0}
  ,
    /* BULK_EMAIL Talks about bulk email */
  {
  "(?i)bulk e-*mail", 0.01}
  ,
    /* CALL_1_800 Contains a 1-800- number */
  {
  "(?i)(?:call|dial).{1,15}1-800-[\\dA-Z]+-?[\\dA-Z]+", 1.93}
  ,
    /* CALL_888 Contains an 888- phone number */
  {
  "(?i)(?:call|dial).{1,15}888-[\\dA-Z]+-?[\\dA-Z]+", 1.00}
  ,
    /* CALL_NOW Urges you to call now */
  {
  "CALL NOW", 1.00}
  ,
    /* CASHCASHCASH Contains at least 3 dollar signs in a row */
  {
  "\\${3,}", 1.64}
  ,
    /* CASINO Contains "Casino" */
  {
  "(?i)casino", 2.00}
  ,
    /* CBYI Contains "CBYI" */
  {
  "CBYI", 2.66}
  ,
    /* CHECK_OR_MONEY_ORDER Talk about a check or money order */
  {
  "(?i)check or money order", 1.65}
  ,
    /* CLICKSFORMONEY_NET Frequent SPAM content */
  {
  "(?i)http://.*clicksformoney\\.net", 1.00}
  ,
    /* CLICK_BELOW Asks you to click below */
  {
  "(?is)click (?:here|below)", 0.01}
  ,
    /* CLICK_HERE_LINK Tells you to click on a URL */
  {
  "(?is)click here.{0,100}</a>", 1.80}
  ,
    /* CLICK_TO_REMOVE_2 Click-to-remove with mailto: found beforehand */
  {
  "(?is)href.{0,50}mailto:.{0,50}click.{0,50}remove", 3.01}
  ,
    /* CLICK_TO_REMOVE_MAILTO Click-to-remove with mailto: found */
  {
  "(?is)\\bclick to.{0,30}remove.{0,50}mailto:", 2.1}
  ,
    /* COMMUNIGATE Communigate is SPAM software */
  {
  "transferred with a trial version of CommuniGate", 4.95}
  ,
    /* COPYRIGHT_CLAIMED Contains a claim of copyright */
  {
  "(?is)copyright.{0,100}all rights reserved", -2.0}
  ,
    /* COPY_DVDS Containts 'Copy DVDs' */
  {
  "(?i)copy.{1,20}dvd", 2.0}
  ,
    /* CYBER_FIRE_POWER mentions Cyber FirePower!, a spam-tool */
  {
  "(?:by|for) Cyber FirePower\\!", 1.21}
  ,
    /* DEAR_FRIEND How dear can you be if you don't know my name? */
  {
  "Dear Friend", 0.90}
  ,
    /* DEAR_SOMEBODY Contains 'Dear Somebody' */
  {
  "Dear [A-Z][a-z]+", 1.0}
  ,
    /* DIFF_C_PATCH Contains what looks like a patch from diff -c */
  {
  "^\\*\\*\\* \\S+ \\S\\S\\S \\S\\S\\S .\\d \\d\\d:\\d\\d:\\d\\d \\d+$", -5.0}
  ,
    /* DIRECT_EMAIL Talks about direct email */
  {
  "(?i)direct e-*mail\\b", 1.57}
  ,
    /* EARN_PER_WEEK Contains 'earn $something per week' */
  {
  "(?i)earn.{1,20}\\d\\d\\d+.{1,30}per week", 2.0}
  ,
    /* EGP_HTML_BANNER non-spam EGP banner found */
  {
  "^<!-- \\|\\*\\*\\|begin egp html banner", -2.0}
  ,
    /* EMAIL_HARVEST Email harvest leads to SPAM for thanksgiving */
  {
  "email harvest", 1.00}
  ,
    /* EMAIL_MARKETING Talks about email marketing */
  {
  "(?i)e-*mail marketing", 1.72}
  ,
    /* EU_200_32_CE Claims compliance with SPAM regulations */
  {
  "(?i)Directive 200.32.CE", 1.00}
  ,
    /* EU_EMAIL_OPTOUT Claims compliance with SPAM regulations */
  {
  "(?i)EU (?:e-?mail opt.?out|e.?commerce) directive", 1.82}
  ,
    /* EXCUSE_1 Gives a lame excuse about why you were sent this SPAM */
  {
  "(?i)You (?:were sent|have received) this message because", 1.00}
  ,
    /* EXCUSE_10 "if you do not wish to receive any more" */
  {
  "(?i)if you (?:(?:want|wish|care|prefer) not to |(?:don\'t|do not) (?:want|wish|care) to )(?:be contacted again|receive (any)?\\s*(?:more|future|further) (?:e?-?mail|messages?|offers|solicitations))",
      1.00}
  ,
    /* EXCUSE_11 Claims you were on a list */
  {
  "(?i)you.{0,15}(?:name|mail).{0,15}(?:was|were).{0,15}list", 1.4}
  ,
    /* EXCUSE_12 Nobody's perfect */
  {
  "(?i)this (?:e?-?mail|message) (?:(?:has )?reached|was sent to) you in error",
      0.01}
  ,
    /* EXCUSE_13 Gives an excuse for why message was sent */
  {
  "(?i)mail was sent to you because ", 0.01}
  ,
    /* EXCUSE_14 Tells you how to stop further SPAM */
  {
  "(?i)you do not wish to receive further ", 0.01}
  ,
    /* EXCUSE_15 Claims to be legitimate email */
  {
  "(?i)this (?:|e?-?mail|message )(?:is|was) (?:not|never) (?:spam|(?:sent |)unsolicited)",
      0.01}
  ,
    /* EXCUSE_16 I wonder how many emails they sent in error... */
  {
  "received this (?:e?-?mail|message) in error[, ]* or", 1.40}
  ,
    /* EXCUSE_17 Suspect you might have received the message by mistake */
  {
  "(?i)received.{0,15} by mistake", 0.70}
  ,
    /* EXCUSE_18 Claims not to be SPAM */
  {
  "(?i)we do not (?:spam|send unsolicited)", 3.4}
  ,
    /* EXCUSE_2 Claims you actually asked for this SPAM */
  {
  "(?i)If you did not opt.in", 1.47}
  ,
    /* EXCUSE_3 Claims you can be removed from the list */
  {
  "(?i)to (?:be removed|be deleted|no longer receive th(?:is|ese) messages?) (?:from|send|reply|[e-]*mail)",
      1.00}
  ,
    /* EXCUSE_4 Claims you can be removed from the list */
  {
  "(?i)To Be Removed,? Please", 1.91}
  ,
    /* EXCUSE_5 Claims you can be removed from the list */
  {
  "(?i)that your email address is removed", 2.20}
  ,
    /* EXCUSE_6 Claims you can be removed from the list */
  {
  "(?:wish to|click to|To) remove yourself", 1.00}
  ,
    /* EXCUSE_7 Claims you can be removed from the list */
  {
  "(?i)you (?:wish|want|would like|desire) to be removed", 0.01}
  ,
    /* EXCUSE_8 Claims you can be removed from the list */
  {
  "requests to be taken off our mailing list", 1.34}
  ,
    /* EXCUSE_9 Claims you can be removed from the list */
  {
  "(?i)If you do.{0,3}n.{0,3}t (?:want|wish|care) to receive emails (?:on this subject|in the future)",
      3.2}
  ,
    /* E_WEBHOSTCENTRAL_URL Frequent SPAM content */
  {
  "(?i)http://.*e-webhostcentral\\.com", 2.32}
  ,
    /* FILTERED_BY_WORLDREMOVE Claims to listen to some removal request list */
  {
  "filtered by WorldRemove", 1.00}
  ,
    /* FORM_W_MAILTO_ACTION Includes a form which will send an email */
  {
  "(?is)action=[3D=\\s\"\']*mailto:", 0.01}
  ,
    /* FOR_FREE No such thing as a free lunch */
  {
  "for FREE", 1.77}
  ,
    /* FOR_INSTANT_ACCESS Instant Access button */
  {
  "(?i)(?:CLICK HERE|).{0,20}\\s+INSTANT\\s+ACCESS.{0,20}\\s+(?:|CLICK HERE)",
      1.99}
  ,
    /* FOR_JUST_SOME_AMT Contains 'for only' some amount of cash */
  {
  "(?i)for (?:just|only) \\$?\\d+\\.?\\d*[^\\.]*!", 0.5}
  ,
    /* FREEWEBCO_NET_URL Frequent SPAM content */
  {
  "(?i)http://.*freewebco\\.net", 1.00}
  ,
    /* FREEWEBHOSTINGCENTRAL Frequent SPAM content */
  {
  "(?i)http://.*freewebhostingcentral", 1.00}
  ,
    /* FREE_CONSULTATION Offers a free consultation */
  {
  "(?i)FREE CONSULTATION", 2.34}
  ,
    /* FREE_PRIORITY_MAIL There's no such thing as a free shipping */
  {
  "(?i)FREE.{0,10} PRIORITY MAIL SHIPPING", 1.4}
  ,
    /* FULL_REFUND Offers a full refund */
  {
  "FULL REFUND", 1.60}
  ,
    /* GAPPY_TEXT Contains 'G.a.p.p.y-T.e.x.t' */
  {
  "(?i)(?:[a-z][-_\\.\\,\\:\\;\'\\~]{1,3}){5,}", 2.5}
  ,
    /* GENTLE_FEROCITY Contains "Gentle Ferocity" */
  {
  "(?i)Gentle Ferocity", 1.00}
  ,
    /* GREAT_OFFER Trying to offer you something */
  {
  "(?i)(?:offer expires|see full offer for details|great offer)", 1.0}
  ,
    /* GREEN_EXCUSE_1 Claims SPAM helps the environment */
  {
  "(?i)using email instead can significantly reduce this", 1.00}
  ,
    /* GREEN_EXCUSE_2 Claims SPAM helps the environment */
  {
  "(?i)the trees, save the planet, use email!", 1.84}
  ,
    /* GUARANTEE Contains word 'guarantee' in all-caps */
  {
  "GUARANTEE", 1.32}
  ,
    /* HOME_EMPLOYMENT Information on how to work at home */
  {
  "(?i)HOME EMPLOYMENT", 2.31}
  ,
    /* HR_3113 Mentions Spam law "H.R. 3113" */
  {
  "(?is)H\\.\\s*R\\.\\s*3113", 1.28}
  ,
    /* HTML_WITH_BGCOLOR HTML mail with non-white background */
  {
  "(?i)<body .*bgcolor[=3d\"\'\\#]+[0-9a-e][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]",
      1.2}
  ,
    /* HTTP_CTRL_CHARS_HOST Uses control sequences inside a URL's hostname */
  {
  "http\\://[^/]*[\\x00-\\x09\\x0b\\x0c\\x0e-\\x1f]", 4.00}
  ,
    /* HTTP_ESCAPED_HOST Uses %-escapes inside a URL's hostname */
  {
  "http\\://[^/]*%", 4.00}
  ,
    /* HTTP_NUMBER_WORD URL contains spamhaus signature: numbered servers */
  {
  "(?i)http\\://(?:zero|one|two|three|four|five|six|seven|eight|nine|ten|eleven|twelve|thirteen|fourteen|fifteen|sixteen|seventeen|eighteen|nineteen|twenty)\\.",
      1.00}
  ,
    /* HTTP_USERNAME_USED Uses a username in a URL */
  {
  "(?is)http\\://[^\\s/]+\\@", 2.58}
  ,
    /* HTTP_WITH_EMAIL_IN_URL 'remove' URL contains an email address */
  {
  "http\\://\\S+=[-_\\+a-z0-9\\.]+\\@[-_\\+a-z0-9\\.]+\\.[-_\\+a-z0-9]{2,3}(?:\\&|\\s)",
      0.80}
  ,
    /* HUNZA_DIET_BREAD Offers a tasty-sounding dietary product */
  {
  "HUNZA DIET BREAD", 0.01}
  ,
    /* INCREASE_SALES Offers increased sales */
  {
  "(?i)INCREASE SALES", 0.90}
  ,
    /* INCREASE_TRAFFIC Instructions on how to boost traffic */
  {
  "(?i)increase.{1,15} traffic\\b", 0.90}
  ,
    /* INTERNET_TERROR_RANT Cyber FirePower! rant about losing dropboxes */
  {
  "(?si)At the time of this mailing the return email address is a bonafide legitimate return email address that was signed up for with the express purpose.{0,30}internet terrorists\\.",
      3.1}
  ,
    /* INTL_EXEC_GUILD Well known SPAM senders */
  {
  "International Executive Guild", 1.65}
  ,
    /* IN_ACCORDANCE_WITH_LAWS Claims to be in accordance with some Spam law */
  {
  "has been sent in accordance with", 1.00}
  ,
    /* ITS_EFFECTIVE Something claims to be effective */
  {
  "(?i)\\bit\'s effective\\b", 1.0}
  ,
    /* JAVASCRIPT JavaScript code */
  {
  "(?i)<SCRIPT.*LANGUAGE.*JavaScript", 0.01}
  ,
    /* JODY Contains "My wife, Jody" testimonial */
  {
  "(?:My wife, Jody|Mi esposa, Jody)", 1.00}
  ,
    /* JUST_MAILED_PAGE Saved web page */
  {
  "(?s)\\n\\n.{0,160}<!-- saved from url=", 0.20}
  ,
    /* KIFF Contains "Temple Kiff" */
  {
  "(?i)temple kiff", 1.00}
  ,
    /* LARGE_HEX Contains a large block of hexadecimal code */
  {
  "[0-9a-fA-F]{70,}", 0.20}
  ,
    /* LASER_PRINTER Discusses laser printer supplies */
  {
  "LASER PRINTER SUPPLIES", 3.89}
  ,
    /* LIMITED_TIME_ONLY Offers a limited time offer */
  {
  "(?i)LIMITED TIME ONLY", 1.27}
  ,
    /* LONG_NUMERIC_HTTP_ADDR Uses a long numeric IP address in URL */
  {
  "(?is)http\\://000\\d+", 1.00}
  ,
    /* MAILMAN_CONFIRM A MailMan confirm-your-address message */
  {
  "We have received a request .*subscription of your email address.* to the .* mailing list",
      -4.0}
  ,
    /* MAILTO_LINK Includes a URL link to send an email */
  {
  "(?is)=[3D=\\s\"\']*mailto:", 0.80}
  ,
    /* MAILTO_TO_REMOVE Includes a 'remove' email address */
  {
  "(?is)remove\\S*\\@\\S+\\.\\S\\S", 1.00}
  ,
    /* MAILTO_TO_SPAM_ADDR Includes a link to a likely spammer email address */
  {
  "(?is)mailto:[a-z]+\\d{2,}\\@", 1.07}
  ,
    /* MAILTO_WITH_SUBJ Includes a link to send a mail with a subject */
  {
  "(?is)mailto:\\S+\\?subject=", 1.27}
  ,
    /* MAILTO_WITH_SUBJ_REMOVE Includes a URL link to send an email with the subject 'remove' */
  {
  "(?is)mailto:\\S+\\?subject=[3D=\\s\"\']*remove", 0.01}
  ,
    /* MAIL_IN_ORDER_FORM Contains mail-in order form */
  {
  "(?i)Mail-in Order Form", 1.00}
  ,
    /* MASS_EMAIL Talks about mass email */
  {
  "(?i)mass e-*mail", 0.01}
  ,
    /* MICRO_CAP_WARNING SEC-mandated penny-stock warning -- thanks SEC */
  {
  "(?i)Investing in micro-cap securities is highly speculative", 1.00}
  ,
    /* MONEY_MAKING Discusses money making */
  {
  "(?i)money making", 0.90}
  ,
    /* MONSTERHUT mentions monsterhut.com */
  {
  "monsterhut.com", 1.00}
  ,
    /* MORTGAGE_RATES Information on mortgage rates */
  {
  "(?i)Mortgage rates", 2.77}
  ,
    /* MURKOWSKI_CRUFT Old Murkowski disclaimer */
  {
  "www\\.senate\\.gov/~?murkowski", 1.30}
  ,
    /* MYCASINOBUILDER Contains "mycasinobuilder.com" */
  {
  "(?i)MYCASINOBUILDER.COM", 3.81}
  ,
    /* NEW_DOMAIN_EXTENSIONS Possible registry spammer */
  {
  "(?i)new\\s*domain\\s*extension", 1.00}
  ,
    /* NIGERIAN_SCAM Nigerian scam, cf http://www.snopes2.com/inboxer/scams/nigeria.htm */
  {
  "BASED ON INFORMATION GATHERED ABOUT YOU, WE BELIEVE\\s*YOU WOULD BE IN A POSITION TO HELP US IN TRANSFER",
      2.6}
  ,
    /* NIGERIAN_SCAM_2 Mutated Nigerian scams */
  {
  "(?:Government of Nigeria|NIGERIAN? NATIONAL|Nigerian? Government)", 0.43}
  ,
    /* NORMAL_HTTP_TO_IP Uses a dotted-decimal IP address in URL */
  {
  "(?is)http\\://\\d+\\.\\d+\\.\\d+\\.\\d+", 1.00}
  ,
    /* NO_QS_ASKED Doesn't ask any questions */
  {
  "NO QUESTIONS ASKED", 3.32}
  ,
    /* NO_SELLING Claims not to be selling anything */
  {
  "absolutely NO selling", 1.8}
  ,
    /* NUMERIC_HTTP_ADDR Uses a numeric IP address in URL */
  {
  "(?is)http\\://\\d{7,}", 3.69}
  ,
    /* ONCE_IN_LIFETIME Once in a lifetime, apparently */
  {
  "(?i)once in a lifetime opportunity", 0.80}
  ,
    /* ONE_HUNDRED_PC_FREE No such thing as a free lunch */
  {
  "100% FREE", 1.28}
  ,
    /* ONE_HUNDRED_PC_GUAR One hundred percent guaranteed */
  {
  "(?i)100% GUARANTEED", 1.43}
  ,
    /* ONE_TIME_MAILING 'one time mailing' doesn't mean it isn't spam */
  {
  "(?i)this\\b.{0,20}\\b(?:one|1).time\\b.{0,20}\\b(?:mail|offer)", 0.01}
  ,
    /* ONLINE_BIZ_OPS Wants you to do business online */
  {
  "(?i)online business opportunities", 1.00}
  ,
    /* OPPORTUNITY Gives information about an opportunity */
  {
  "OPPORTUNITY", 2.85}
  ,
    /* OPT_IN Talks about opting in */
  {
  "(?i)\\bopt-in\\b", 1.24}
  ,
    /* PARA_A_2_C_OF_1618 Claims compliance with senate bill 1618 */
  {
  "(?i)Paragraph .a.{0,10}2.{0,10}C. of S. 1618", 3.01}
  ,
    /* PENIS_ENLARGE Information on getting a larger penis */
  {
  "(?is)(?:(?:\\bpenis\\b|\\benlarge).{0,50}){2,}", 1.92}
  ,
    /* PENNIES_A_DAY Contains 'for only pennies a day' */
  {
  "(?i)for (?:just|only) pennies a day", 2.0}
  ,
    /* PGP_SIGNATURE Contains a PGP-signed message */
  {
  "-----BEGIN PGP SIGNATURE-----", -5.0}
  ,
    /* POPLAUNCH SPAM software */
  {
  "StealthLaunch PopLaunch.\\s", 1.01}
  ,
    /* PREST_NON_ACCREDITED 'Prestigious Non-Accredited Universities' */
  {
  "(?i)prestigi?ous\\b.{0,20}\\bnon-accredited\\b.{0,20}\\buniversities", 1.93}
  ,
    /* PRINT_FORM_SIGNATURE Asks you for your signature on a form */
  {
  "(?i)Sign(ature)?(?:\\s*here|\\s*please)?:.{0,30}___*", 1.00}
  ,
    /* PRINT_OUT_AND_FAX Contains words 'print out and fax' */
  {
  "(?i)print\\s+out\\s+and\\s+fax", 1.0}
  ,
    /* PRODUCED_AND_SENT_OUT Tells you it's an ad */
  {
  "This a.?d is produced and sent out by", 1.28}
  ,
    /* PROFITS Contains word 'profits' in all-caps */
  {
  "PROFITS", 0.70}
  ,
    /* PURE_PROFIT Profit is dirty, not pure */
  {
  "PURE PROFIT", 2.67}
  ,
    /* REALLY_UNSAFE_JAVASCRIPT Auto-executing JavaScript code */
  {
  "(?i)<body .*onLoad", 1.30}
  ,
    /* RELAYING_FRAME Frame wanted to load outside URL */
  {
  "(?is)<frame\\b[^>]+\\bsrc=[3D=\\s\"\']*http://", 4.4}
  ,
    /* REMOVAL_INSTRUCTIONS Gives instructions for removal from list */
  {
  "(?i)REMOVAL INSTRUCTIONS", 1.00}
  ,
    /* REMOVE_IN_QUOTES List removal information */
  {
  "(?i)\"remove\"", 0.01}
  ,
    /* REMOVE_PAGE URL of page called "remove" */
  {
  "https?://[^/]+/remove", 2.31}
  ,
    /* REMOVE_SCRIPT URL of CGI script called "remove" */
  {
  "https?://.*cgi.*/remove\\.", 0.01}
  ,
    /* REMOVE_SUBJ List removal information */
  {
  "(?i)remove.{1,15}subject", 1.00}
  ,
    /* REPLY_REMOVE_SUBJECT List removal information */
  {
  "(?i)reply.{1,15}remove.{1,15}subject", 1.00}
  ,
    /* RESISTANCE_IS_FUTILE Resistance to this spam is futile */
  {
  "Replying to this email will not unsubscribe you.", 1.0}
  ,
    /* SECTION_301 Claims compliance with SPAM regulations */
  {
  "(?i)SECTION.{0,10}301", 1.24}
  ,
    /* SENT_IN_COMPLIANCE Claims compliance with SPAM regulations */
  {
  "message .{0,10}sen(?:d|t) in compliance (?:of|with)", 1.33}
  ,
    /* SEXY_PICS Sexy pictures */
  {
  "sexy pictures", 0.01}
  ,
    /* SHOES_GUY Want some shoes? */
  {
  "(?i)(?:\\b(?:Lingui|Guilin)\\b.{1,30}){2,}", 3.9}
  ,
    /* SLIGHTLY_UNSAFE_JAVASCRIPT JavaScript code which can easily be executed */
  {
  "(?i)on(?:Blur|Error|KeyDown|KeyUp|Load|MouseOver|Resize|Unload)", 1.00}
  ,
    /* SOCIAL_SEC_NUMBER Talks about social security numbers */
  {
  "(?i)social security (?:number|record)", 3.73}
  ,
    /* SPAM_FORM Form for changing email address */
  {
  "CHANGE EMAIL ADDRESS IN ACTION OF FORM", 3.25}
  ,
    /* SPAM_FORM_INPUT Form for verifying email address */
  {
  "(?i)<input name=.*submit type=.*submit value=.*\" *Submit By E-Mail *\">",
      4.0}
  ,
    /* SPAM_FORM_RETURN Form for checking email address */
  {
  "return validate_form", 1.00}
  ,
    /* STOCK_ALERT Offers a stock alert */
  {
  "(?i)stock alert", 1.00}
  ,
    /* STOCK_PICK Offers a stock pick */
  {
  "STOCK PICK", 1.00}
  ,
    /* STRONG_BUY Tells you about a strong buy */
  {
  "(?i)strong buy", 4.82}
  ,
    /* SUBJ_2_CREDIT Contains 'subject to credit approval' */
  {
  "(?i)subject to credit approval", 1.0}
  ,
    /* SUBJ_REMOVE List removal information */
  {
  "(?i)subject.{1,15}remove", 0.01}
  ,
    /* SUPERLONG_LINE Contains a line >=199 characters long */
  {
  "(?m)^[^<]{199,}$", 0.01}
  ,
    /* S_1618 Claims compliance with senate bill 1618 */
  {
  "(?i)S..{0,10}1618.{0,10}-.{0,10}SECTION.{0,10}301", 3.50}
  ,
    /* TAKE_ACTION_NOW Tells you to 'take action now!' */
  {
  "(?i)take action now!", 3.16}
  ,
    /* THE_FOLLOWING_FORM Asks you to fill out a form */
  {
  "the following form\\b", 1.79}
  ,
    /* THIS_AINT_SPAM Claims "This is not spam" */
  {
  "(?is)This.{0,30}is not spam", 2.17}
  ,
    /* TONER Contains "Toner Cartridge" */
  {
  "(?i)toner cartridge", 2.78}
  ,
    /* TO_BE_REMOVED_REPLY Says: "to be removed, reply via email" or similar */
  {
  "(?is)\\bto\\b.{0,20}\\bremove.{0,20}\\breply\\b", 1.82}
  ,
    /* TO_UNSUB_REPLY Says: "to unsubscribe, reply via email" or similar */
  {
  "(?is)\\bto\\b.{0,20}\\bunsubscribe.{0,20}\\breply\\b", 1.81}
  ,
    /* TRACE_BY_SSN Talks about tracing by SSN */
  {
  "(?i)Trace anyone by social security number", 1.27}
  ,
    /* TRACKER_ID Incorporates a tracking ID number */
  {
  "^\\W{4,6} (?:[a-z]{10,}|[A-Z]{10,}) \\W{4,6}\\s*$", 0.71}
  ,
    /* UCE_MAIL_ACT Mentions Spam Law "UCE-Mail Act" */
  {
  "Unsolicited Commercial Electronic Mail Act", 4.0}
  ,
    /* UNIFIED_PATCH Contains what looks like a patch from diff -u */
  {
  "^\\@\\@ [-+0-9]+,[0-9]+ [-+0-9]+,[0-9]+ \\@\\@$", -5.0}
  ,
    /* UNIVERSITY_DIPLOMAS University Diplomas */
  {
  "(?i)\\b(?:college|university)\\s+diplomas", 1.29}
  ,
    /* UNNEEDED_HTML_ENCODING Unneeded encoding of HTML tags */
  {
  "(?i)font=3E", 3.5}
  ,
    /* UNSUB_PAGE URL of page called "unsubscribe" */
  {
  "https?://[^/]+/unsubscribe", 1.21}
  ,
    /* UNSUB_SCRIPT URL of CGI script called "unsubscribe" */
  {
  "https?://.*cgi.*/unsubscribe\\.", 2.17}
  ,
    /* URGENT_BIZ Containts 'URGENT BUSINESS' */
  {
  "URGENT BUSINESS", 1.0}
  ,
    /* US_DOLLARS Nigerian scam key phrase */
  {
  "(?i)Million\\b.{0,40}\\b(?:United States Dollars|USD)", 0.30}
  ,
    /* VIAGRA Plugs Viagra */
  {
  "VIAGRA", 1.00}
  ,
    /* VJESTIKA Contains "Vjestika Aphrodisia" */
  {
  "(?i)Vjestika Aphrodisia", 1.00}
  ,
    /* WANTS_CREDIT_CARD Asks for credit card details */
  {
  "(?i)\\bcredit.?card\\s+order", 1.31}
  ,
    /* WEB_BUGS Image tag with an ID code to identify you */
  {
  "(?i)<\\s*img\\s[^>]*src[^>]+\\?", 1.00}
  ,
    /* WE_HATE_SPAM Says "We strongly oppose the use of SPAM email" */
  {
  "(?is)We .{0,30}oppose the use of SPAM", 1.00}
  ,
    /* WE_HONOR_ALL Claims to honor removal requests */
  {
  "(?i)we (?:honou?r|respect)(?: all|) remov[eal] requests", 1.65}
  ,
    /* WORK_AT_HOME Information on how to work at home */
  {
  "(?:WORK (?:AT|FROM) HOME|HOME.?WORKER)", 1.00}
  ,
    /* WWW_AUTOREMOVE_COM Frequent SPAM content */
  {
  "(?i)http://.*autoremove\\.com", 1.92}
  ,
    /* WWW_DIRECTFORCEMARKETING_COM Frequent SPAM content */
  {
  "(?i)http://.*directforcemarketing\\.com", 1.00}
  ,
    /* WWW_NETSITESFORFREE_NET Frequent SPAM content */
  {
  "(?i)http://.*netsitesforfree\\.net", 1.00}
  ,
    /* WWW_REMOVEYOU_COM Frequent SPAM content */
  {
  "(?i)http://.*removeyou\\.com", 1.32}
  ,
    /* YELLOWSUN Frequent SPAM content */
  {
  "(?i)yellowsun01\\.com", 1.00}
  ,
    /* YOUR_INCOME Doing something with my income */
  {
  "(?i)\\byour income\\b", 1.00}
  ,
    /* YOU_HAVE_BEEN_SELECTED "You have been selected as a finalist", sure */
  {
  "(?i)You have been selected as a (?:finalist|winner)", 1.43}
  , {
  NULL, 0.0}
,};

struct racist_pattern
{
  char *pattern;
  float score;
}
racist_pattern[] =
{
  {
  "(?i)\\bnigger\\b", 1.0}
  , {
  "(?i)\\bcoon\\b", 1.0}
  , {
  "(?i)\\bcoons\\b", 1.0}
  , {
  "(?i)\\bcornhole\\b", 1.0}
  , {
  "(?i)\\bcotton picker\\b", 1.0}
  , {
  "(?i)\\bcotton pickers\\b", 1.0}
  , {
  "(?i)\\bdarky\\b", 1.0}
  , {
  "(?i)\\bnigga\\b", 1.0}
  , {
  "(?i)\\bnigger\\b", 1.0}
  , {
  "(?i)\\bniggers\\b", 1.0}
  , {
  "(?i)\\bpecker cheese\\b", 1.0}
  , {
  "(?i)\\bpecker\\b", 1.0}
  , {
  "(?i)\\bpeckers\\b", 1.0}
  , {
  "(?i)\\bpeckerwood\\b", 1.0}
  , {
  "(?i)\\bpeckerwoods\\b", 1.0}
  , {
  "(?i)\\btar baby\\b", 1.0}
  , {
  "(?i)\\bwetback\\b", 1.0}
  , {
  "(?i)\\bwetbacks\\b", 1.0}
  , {
  "(?i)\\bgook\\b", 1.0}
  , {
  "(?i)\\bgooks\\b", 1.0}
  , {
  "(?i)\\bfag\\b", 1.0}
  , {
  "(?i)\\bfags\\b", 1.0}
  , {
  "(?i)\\bfaggot\\b", 1.0}
  , {
  "(?i)\\bkike\\b", 1.0}
  , {
  "(?i)\\bdyke\\b", 1.0}
  , {
  "(?i)\\bqueers\\b", 1.0}
  , {
  "(?i)\\bdykes\\b", 1.0}
  , {
  "(?i)\\bfaggots\\b", 1.0}
  , {
  NULL, 0.0}
,};

struct porn_pattern
{
  char *pattern;
  float score;
}
porn_pattern[] =
{
  /* WEB4PORNO_URL Frequent SPAM content */
  {
  "(?i)http://.*web4porno\\.com", 2.77}
  ,
    /* PORN_1 Uses words and phrases which indicate porn (1) */
  {
  "(?i)\\bbarely\\b.{0,15}\\blegal\\b", 2.93}
  ,
    /* PORN_2 Uses words and phrases which indicate porn (2) */
  {
  "(?i)\\bwild\\b.{0,15}\\bhardcore\\b", 2.23}
  ,
    /* PORN_3 Uses words and phrases which indicate porn (3) */
  {
  "(?i)(?:(?:\\bcum|\\borg[iy]|\\bwild|fuck|\\bteen|\\baction\\b|spunk|\\bpussy\\b|\\bpussies\\b|suck\\b|sucking\\b|\\bhot\\b|\\bhottest\\b|\\bvoyeur|\\ble[sz]b(?:ian|o)|\\banal\\b|\\binterracial|\\basian\\b|\\bamateur|\\bsex+\\b|\\bslut|explicit|xxx[^x]|\\blive\\b|celebrity|\\blick|\\bsuck|\\bdorm\\b|webcam|\\bass\\b|\\bschoolgirl\\b|\\bstrip|\\bhorny\\b|\\bhorniest\\b|\\berotic|\\boral\\b|\\bhardcore\\b|\\bblow[ -]*job|\\bnast(?:y|iest)\\b|\\bporn).{0,15}){3,}",
      2.70}
  ,
    /* PORN_4 Uses words and phrases which indicate porn (4) */
  {
  "http://[\\w\\.]*(?:xxx|sex|anal|slut|pussy|cum|nympho|suck|porn|hardcore|taboo|whore|voyeur|lesbian|gurlpages|naughty|lolita|teen|schoolgirl|kooloffer|erotic)\\w*\\.",
      1.80}
  ,
    /* PORN_6 Uses words and phrases which indicate porn (6) */
  {
  "(?i)(?:\\d+\\+? xxx pictures|xxx photos?)", 1.32}
  ,
    /* PORN_7 Uses words and phrases which indicate porn (7) */
  {
  "(?i)Free XXX", 0.5}
  ,
    /* PORN_8 Uses words and phrases which indicate porn (8) */
  {
  "(?:video|movie|teen|ware|mp3)z", 0.45}
  , {
  "(?i)\\btranssexual\\b", 1.0}
  , {
  "(?i)\\bshemale\\b", 1.0}
  , {
  "(?i)\\bfuck\\b", 1.0}
  , {
  "(?i)\\bcunt\\b", 1.0}
  , {
  "(?i)\\bass\\b", 1.0}
  , {
  "(?i)\\bassfuck\\b", 1.0}
  , {
  "(?i)\\basshole\\b", 1.0}
  , {
  "(?i)\\bassholes\\b", 1.0}
  , {
  "(?i)\\basswipe\\b", 1.0}
  , {
  "(?i)\\basswipes\\b", 1.0}
  , {
  "(?i)\\bbastard\\b", 1.0}
  , {
  "(?i)\\bbitch\\b", 1.0}
  , {
  "(?i)\\bblow job\\b", 1.0}
  , {
  "(?i)\\bblowjob\\b", 1.0}
  , {
  "(?i)\\bblowjobs\\b", 1.0}
  , {
  "(?i)\\bclit\\b", 1.0}
  , {
  "(?i)\\bcock ring\\b", 1.0}
  , {
  "(?i)\\bcock\\b", 1.0}
  , {
  "(?i)\\bcocks\\b", 1.0}
  , {
  "(?i)\\bcocksucker\\b", 1.0}
  , {
  "(?i)\\bcocksuckers\\b", 1.0}
  , {
  "(?i)\\bcome stain\\b", 1.0}
  , {
  "(?i)\\bcome stains\\b", 1.0}
  , {
  "(?i)\\bcum\\b", 1.0}
  , {
  "(?i)\\bcunts\\b", 1.0}
  , {
  "(?i)\\bdick\\b", 1.0}
  , {
  "(?i)\\bdicks\\b", 1.0}
  , {
  "(?i)\\bdickwad\\b", 1.0}
  , {
  "(?i)\\bdickwads\\b", 1.0}
  , {
  "(?i)\\bdildo\\b", 1.0}
  , {
  "(?i)\\bdildos\\b", 1.0}
  , {
  "(?i)\\bdipshit\\b", 1.0}
  , {
  "(?i)\\bdipshits\\b", 1.0}
  , {
  "(?i)\\bfuck\\b", 1.0}
  , {
  "(?i)\\bfucked\\b", 1.0}
  , {
  "(?i)\\bfucker\\b", 1.0}
  , {
  "(?i)\\bfuckin\\b", 1.0}
  , {
  "(?i)\\bfucking\\b", 1.0}
  , {
  "(?i)\\bgangbang\\b", 1.0}
  , {
  "(?i)\\bhair pie\\b", 1.0}
  , {
  "(?i)\\bhard-on\\b", 1.0}
  , {
  "(?i)\\bhard on\\b", 1.0}
  , {
  "(?i)\\bhardon\\b", 1.0}
  , {
  "(?i)\\bjack off\\b", 1.0}
  , {
  "(?i)\\bjackshit\\b", 1.0}
  , {
  "(?i)\\bjizz\\b", 1.0}
  , {
  "(?i)\\bjizzum\\b", 1.0}
  , {
  "(?i)\\bmother fucker\\b", 1.0}
  , {
  "(?i)\\bmother fucking\\b", 1.0}
  , {
  "(?i)\\bmotherfucker\\b", 1.0}
  , {
  "(?i)\\bmotherfucking\\b", 1.0}
  , {
  "(?i)\\bmotherfuckin\\b", 1.0}
  , {
  "(?i)\\bmuff diver\\b", 1.0}
  , {
  "(?i)\\boh shit\\b", 1.0}
  , {
  "(?i)\\bpiss\\b", 1.0}
  , {
  "(?i)\\bpiss off\\b", 1.0}
  , {
  "(?i)\\bpissed\\b", 1.0}
  , {
  "(?i)\\bpubes\\b", 1.0}
  , {
  "(?i)\\bpussies\\b", 1.0}
  , {
  "(?i)\\bpussy\\b", 1.0}
  , {
  "(?i)\\bpussys\\b", 1.0}
  , {
  "(?i)\\bqueer\\b", 1.0}
  , {
  "(?i)\\brim job\\b", 1.0}
  , {
  "(?i)\\bshit\\b", 1.0}
  , {
  "(?i)\\bshitcan\\b", 1.0}
  , {
  "(?i)\\bshitfaced\\b", 1.0}
  , {
  "(?i)\\bshitfit\\b", 1.0}
  , {
  "(?i)\\bshithead\\b", 1.0}
  , {
  "(?i)\\bshithouse\\b", 1.0}
  , {
  "(?i)\\bshitlist\\b", 1.0}
  , {
  "(?i)\\bshits\\b", 1.0}
  , {
  "(?i)\\bshot your load\\b", 1.0}
  , {
  "(?i)\\bshot your wad\\b", 1.0}
  , {
  "(?i)\\bshoot your load\\b", 1.0}
  , {
  "(?i)\\bshoot your wad\\b", 1.0}
  , {
  "(?i)\\bsixty-nine\\b", 1.0}
  , {
  "(?i)\\bsixty-niner\\b", 1.0}
  , {
  "(?i)\\bskull fuck\\b", 1.0}
  , {
  "(?i)\\bslut\\b", 1.0}
  , {
  "(?i)\\bsluts\\b", 1.0}
  , {
  "(?i)\\bsnatch\\b", 1.0}
  , {
  "(?i)\\bson of a bitch\\b", 1.0}
  , {
  "(?i)\\bspooge\\b", 1.0}
  , {
  "(?i)\\bspunk\\b", 1.0}
  , {
  "(?i)\\bsuck\\b", 1.0}
  , {
  "(?i)\\bsucking\\b", 1.0}
  , {
  "(?i)\\btake a crap\\b", 1.0}
  , {
  "(?i)\\btake a dump\\b", 1.0}
  , {
  "(?i)\\btake a piss\\b", 1.0}
  , {
  "(?i)\\btake a shit\\b", 1.0}
  , {
  "(?i)\\bshit hit the fan\\b", 1.0}
  , {
  "(?i)\\btit\\b", 1.0}
  , {
  "(?i)\\btits\\b", 1.0}
  , {
  "(?i)\\btittie\\b", 1.0}
  , {
  "(?i)\\btitty fuck\\b", 1.0}
  , {
  "(?i)\\btwat\\b", 1.0}
  , {
  "(?i)\\bup shit creek\\b", 1.0}
  , {
  "(?i)\\bwhack off\\b", 1.0}
  , {
  NULL, 0.0}
,};

#endif /* _BODY_PATTERNS_H */

