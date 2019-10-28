/* C++ code produced by gperf version 3.1 */
/* Command-line: /usr/bin/gperf -e , -L C++ -Z LogTagHash -t -N lookup logtags.gperf  */
/* Computed positions: -k'1-2,6,$' */

#if !((' ' == 32) && ('!' == 33) && ('"' == 34) && ('#' == 35) \
      && ('%' == 37) && ('&' == 38) && ('\'' == 39) && ('(' == 40) \
      && (')' == 41) && ('*' == 42) && ('+' == 43) && (',' == 44) \
      && ('-' == 45) && ('.' == 46) && ('/' == 47) && ('0' == 48) \
      && ('1' == 49) && ('2' == 50) && ('3' == 51) && ('4' == 52) \
      && ('5' == 53) && ('6' == 54) && ('7' == 55) && ('8' == 56) \
      && ('9' == 57) && (':' == 58) && (';' == 59) && ('<' == 60) \
      && ('=' == 61) && ('>' == 62) && ('?' == 63) && ('A' == 65) \
      && ('B' == 66) && ('C' == 67) && ('D' == 68) && ('E' == 69) \
      && ('F' == 70) && ('G' == 71) && ('H' == 72) && ('I' == 73) \
      && ('J' == 74) && ('K' == 75) && ('L' == 76) && ('M' == 77) \
      && ('N' == 78) && ('O' == 79) && ('P' == 80) && ('Q' == 81) \
      && ('R' == 82) && ('S' == 83) && ('T' == 84) && ('U' == 85) \
      && ('V' == 86) && ('W' == 87) && ('X' == 88) && ('Y' == 89) \
      && ('Z' == 90) && ('[' == 91) && ('\\' == 92) && (']' == 93) \
      && ('^' == 94) && ('_' == 95) && ('a' == 97) && ('b' == 98) \
      && ('c' == 99) && ('d' == 100) && ('e' == 101) && ('f' == 102) \
      && ('g' == 103) && ('h' == 104) && ('i' == 105) && ('j' == 106) \
      && ('k' == 107) && ('l' == 108) && ('m' == 109) && ('n' == 110) \
      && ('o' == 111) && ('p' == 112) && ('q' == 113) && ('r' == 114) \
      && ('s' == 115) && ('t' == 116) && ('u' == 117) && ('v' == 118) \
      && ('w' == 119) && ('x' == 120) && ('y' == 121) && ('z' == 122) \
      && ('{' == 123) && ('|' == 124) && ('}' == 125) && ('~' == 126))
/* The character set is not based on ISO-646.  */
#error "gperf generated tables don't work with this execution character set. Please report a bug to <bug-gperf@gnu.org>."
#endif

#line 4 "logtags.gperf"
struct tagid { char *name; int id; };

#define TOTAL_KEYWORDS 143
#define MIN_WORD_LENGTH 8
#define MAX_WORD_LENGTH 17
#define MIN_HASH_VALUE 9
#define MAX_HASH_VALUE 368
/* maximum key range = 360, duplicates = 0 */

class LogTagHash
{
private:
  static inline unsigned int hash (const char *str, size_t len);
public:
  static const struct tagid *lookup (const char *str, size_t len);
};

inline unsigned int
LogTagHash::hash (const char *str, size_t len)
{
  static const unsigned short asso_values[] =
    {
      369, 369, 369, 369, 369, 369, 369, 369, 369, 369,
      369, 369, 369, 369, 369, 369, 369, 369, 369, 369,
      369, 369, 369, 369, 369, 369, 369, 369, 369, 369,
      369, 369, 369, 369, 369, 369, 369, 369, 369, 369,
      369, 369, 369, 369, 369, 369,  65, 369, 369, 369,
       80, 369, 369, 369, 369, 369, 369, 369, 369, 369,
      369, 369, 369, 369, 369, 369, 369, 369, 369, 369,
      369, 369, 369, 369, 369, 369, 369, 369, 369, 369,
      369, 369, 369, 369, 369, 369, 369, 369, 369, 369,
      369, 369, 369, 369, 369, 369, 369, 135, 195,  80,
      100,   5,  90,   5,  35,  60,  45, 369, 110, 115,
       15,  35,  10,  50,   0,  25,   0, 120,  15,  15,
       75,   0, 369, 369, 369, 369, 369, 369, 369, 369,
      369, 369, 369, 369, 369, 369, 369, 369, 369, 369,
      369, 369, 369, 369, 369, 369, 369, 369, 369, 369,
      369, 369, 369, 369, 369, 369, 369, 369, 369, 369,
      369, 369, 369, 369, 369, 369, 369, 369, 369, 369,
      369, 369, 369, 369, 369, 369, 369, 369, 369, 369,
      369, 369, 369, 369, 369, 369, 369, 369, 369, 369,
      369, 369, 369, 369, 369, 369, 369, 369, 369, 369,
      369, 369, 369, 369, 369, 369, 369, 369, 369, 369,
      369, 369, 369, 369, 369, 369, 369, 369, 369, 369,
      369, 369, 369, 369, 369, 369, 369, 369, 369, 369,
      369, 369, 369, 369, 369, 369, 369, 369, 369, 369,
      369, 369, 369, 369, 369, 369, 369, 369, 369, 369,
      369, 369, 369, 369, 369, 369, 369
    };
  return len + asso_values[static_cast<unsigned char>(str[5])] + asso_values[static_cast<unsigned char>(str[1]+1)] + asso_values[static_cast<unsigned char>(str[0])] + asso_values[static_cast<unsigned char>(str[len - 1])];
}

const struct tagid *
LogTagHash::lookup (const char *str, size_t len)
{
  static const struct tagid wordlist[] =
    {
      {"",0}, {"",0}, {"",0}, {"",0}, {"",0}, {"",0}, {"",0},
      {"",0}, {"",0},
#line 96 "logtags.gperf"
      {"rsh.error", 90},
      {"",0}, {"",0}, {"",0}, {"",0},
#line 89 "logtags.gperf"
      {"rdp.error", 83},
      {"",0}, {"",0},
#line 132 "logtags.gperf"
      {"tftp.request", 126},
      {"",0},
#line 95 "logtags.gperf"
      {"rsh.debug", 89},
#line 130 "logtags.gperf"
      {"tftp.error", 124},
      {"",0}, {"",0}, {"",0},
#line 88 "logtags.gperf"
      {"rdp.debug", 82},
#line 80 "logtags.gperf"
      {"pssl.error", 74},
#line 131 "logtags.gperf"
      {"tftp.policy", 125},
      {"",0}, {"",0}, {"",0},
#line 76 "logtags.gperf"
      {"pop3.reply", 70},
#line 81 "logtags.gperf"
      {"pssl.policy", 75},
#line 77 "logtags.gperf"
      {"pop3.request", 71},
      {"",0},
#line 119 "logtags.gperf"
      {"ssh.error", 113},
#line 74 "logtags.gperf"
      {"pop3.error", 68},
#line 92 "logtags.gperf"
      {"rdp.session", 86},
#line 115 "logtags.gperf"
      {"sqlnet.error", 109},
      {"",0},
#line 116 "logtags.gperf"
      {"sqlnet.request", 110},
      {"",0},
#line 75 "logtags.gperf"
      {"pop3.policy", 69},
      {"",0}, {"",0},
#line 118 "logtags.gperf"
      {"ssh.debug", 112},
#line 97 "logtags.gperf"
      {"rsh.policy", 91},
      {"",0}, {"",0}, {"",0},
#line 133 "logtags.gperf"
      {"tftp.violation", 127},
#line 91 "logtags.gperf"
      {"rdp.policy", 85},
      {"",0},
#line 112 "logtags.gperf"
      {"smtp.request", 106},
      {"",0}, {"",0},
#line 109 "logtags.gperf"
      {"smtp.error", 103},
#line 117 "logtags.gperf"
      {"sqlnet.violation", 111},
      {"",0},
#line 113 "logtags.gperf"
      {"smtp.response", 107},
#line 136 "logtags.gperf"
      {"vnc.error", 130},
#line 66 "logtags.gperf"
      {"nntp.reply", 60},
#line 111 "logtags.gperf"
      {"smtp.policy", 105},
#line 67 "logtags.gperf"
      {"nntp.request", 61},
#line 90 "logtags.gperf"
      {"rdp.info", 84},
#line 78 "logtags.gperf"
      {"pop3.violation", 72},
#line 68 "logtags.gperf"
      {"nntp.trace", 62},
      {"",0}, {"",0}, {"",0},
#line 135 "logtags.gperf"
      {"vnc.debug", 129},
#line 120 "logtags.gperf"
      {"ssh.policy", 114},
#line 65 "logtags.gperf"
      {"nntp.policy", 59},
      {"",0}, {"",0}, {"",0}, {"",0}, {"",0}, {"",0}, {"",0},
#line 105 "logtags.gperf"
      {"sip.error", 99},
      {"",0},
#line 139 "logtags.gperf"
      {"vnc.session", 133},
      {"",0},
#line 123 "logtags.gperf"
      {"ssh.info", 117},
#line 114 "logtags.gperf"
      {"smtp.violation", 108},
#line 42 "logtags.gperf"
      {"imap.reply", 36},
#line 101 "logtags.gperf"
      {"sip.request", 95},
#line 43 "logtags.gperf"
      {"imap.request", 37},
#line 98 "logtags.gperf"
      {"rsh.violation", 92},
#line 104 "logtags.gperf"
      {"sip.debug", 98},
#line 39 "logtags.gperf"
      {"imap.error", 33},
      {"",0},
#line 102 "logtags.gperf"
      {"sip.response", 96},
#line 93 "logtags.gperf"
      {"rdp.violation", 87},
      {"",0},
#line 138 "logtags.gperf"
      {"vnc.policy", 132},
#line 41 "logtags.gperf"
      {"imap.policy", 35},
      {"",0}, {"",0},
#line 94 "logtags.gperf"
      {"rsh.accounting", 88},
      {"",0}, {"",0},
#line 125 "logtags.gperf"
      {"telnet.error", 119},
#line 126 "logtags.gperf"
      {"telnet.policy", 120},
      {"",0},
#line 11 "logtags.gperf"
      {"core.error", 5},
      {"",0},
#line 124 "logtags.gperf"
      {"telnet.debug", 118},
#line 137 "logtags.gperf"
      {"vnc.info", 131},
      {"",0}, {"",0},
#line 15 "logtags.gperf"
      {"core.policy", 9},
      {"",0},
#line 121 "logtags.gperf"
      {"ssh.violation", 115},
      {"",0},
#line 103 "logtags.gperf"
      {"sip.policy", 97},
      {"",0}, {"",0}, {"",0},
#line 44 "logtags.gperf"
      {"imap.violation", 38},
#line 129 "logtags.gperf"
      {"tftp.debug", 123},
#line 127 "logtags.gperf"
      {"telnet.violation", 121},
      {"",0}, {"",0},
#line 122 "logtags.gperf"
      {"ssh.accounting", 116},
#line 79 "logtags.gperf"
      {"pssl.debug", 73},
#line 17 "logtags.gperf"
      {"core.stderr", 11},
#line 48 "logtags.gperf"
      {"ldap.request", 42},
      {"",0}, {"",0},
#line 46 "logtags.gperf"
      {"ldap.error", 40},
      {"",0},
#line 128 "logtags.gperf"
      {"telnet.violations", 122},
#line 49 "logtags.gperf"
      {"ldap.response", 43},
      {"",0},
#line 73 "logtags.gperf"
      {"pop3.debug", 67},
#line 47 "logtags.gperf"
      {"ldap.policy", 41},
      {"",0},
#line 140 "logtags.gperf"
      {"vnc.violation", 134},
      {"",0},
#line 70 "logtags.gperf"
      {"plug.error", 64},
      {"",0},
#line 16 "logtags.gperf"
      {"core.session", 10},
      {"",0},
#line 110 "logtags.gperf"
      {"smtp.info", 104},
      {"",0},
#line 71 "logtags.gperf"
      {"plug.policy", 65},
#line 19 "logtags.gperf"
      {"finger.error", 13},
#line 20 "logtags.gperf"
      {"finger.policy", 14},
#line 21 "logtags.gperf"
      {"finger.request", 15},
      {"",0},
#line 142 "logtags.gperf"
      {"whois.error", 136},
#line 18 "logtags.gperf"
      {"finger.debug", 12},
#line 143 "logtags.gperf"
      {"whois.request", 137},
      {"",0},
#line 108 "logtags.gperf"
      {"smtp.debug", 102},
#line 141 "logtags.gperf"
      {"whois.debug", 135},
      {"",0},
#line 100 "logtags.gperf"
      {"sip.violation", 94},
#line 50 "logtags.gperf"
      {"ldap.violation", 44},
      {"",0}, {"",0}, {"",0}, {"",0},
#line 145 "logtags.gperf"
      {"x11.error", 139},
#line 64 "logtags.gperf"
      {"nntp.debug", 58},
#line 22 "logtags.gperf"
      {"finger.violation", 16},
#line 35 "logtags.gperf"
      {"http.request", 29},
#line 52 "logtags.gperf"
      {"lp.error", 46},
#line 106 "logtags.gperf"
      {"sip.accounting", 100},
#line 33 "logtags.gperf"
      {"http.error", 27},
      {"",0}, {"",0},
#line 36 "logtags.gperf"
      {"http.response", 30},
#line 144 "logtags.gperf"
      {"x11.debug", 138},
#line 55 "logtags.gperf"
      {"mime.error", 49},
#line 34 "logtags.gperf"
      {"http.policy", 28},
#line 72 "logtags.gperf"
      {"plug.session", 66},
      {"",0},
#line 40 "logtags.gperf"
      {"imap.info", 34},
      {"",0},
#line 56 "logtags.gperf"
      {"mime.policy", 50},
      {"",0}, {"",0}, {"",0}, {"",0},
#line 148 "logtags.gperf"
      {"x11.session", 142},
      {"",0}, {"",0}, {"",0},
#line 38 "logtags.gperf"
      {"imap.debug", 32},
#line 59 "logtags.gperf"
      {"msrpc.error", 53},
#line 61 "logtags.gperf"
      {"msrpc.policy", 55},
      {"",0},
#line 12 "logtags.gperf"
      {"core.info", 6},
#line 107 "logtags.gperf"
      {"smtp.accounting", 101},
#line 58 "logtags.gperf"
      {"msrpc.debug", 52},
      {"",0}, {"",0},
#line 37 "logtags.gperf"
      {"http.violation", 31},
#line 147 "logtags.gperf"
      {"x11.policy", 141},
      {"",0}, {"",0}, {"",0},
#line 57 "logtags.gperf"
      {"mime.violation", 51},
#line 9 "logtags.gperf"
      {"core.debug", 3},
      {"",0}, {"",0},
#line 62 "logtags.gperf"
      {"msrpc.session", 56},
#line 10 "logtags.gperf"
      {"core.dump", 4},
#line 63 "logtags.gperf"
      {"msrpc.violation", 57},
      {"",0}, {"",0},
#line 146 "logtags.gperf"
      {"x11.info", 140},
#line 134 "logtags.gperf"
      {"tls.accounting", 128},
      {"",0}, {"",0},
#line 13 "logtags.gperf"
      {"core.license", 7},
      {"",0},
#line 24 "logtags.gperf"
      {"ftp.error", 18},
#line 54 "logtags.gperf"
      {"lp.request", 48},
      {"",0},
#line 14 "logtags.gperf"
      {"core.message", 8},
      {"",0},
#line 26 "logtags.gperf"
      {"ftp.reply", 20},
#line 60 "logtags.gperf"
      {"msrpc.info", 54},
#line 27 "logtags.gperf"
      {"ftp.request", 21},
      {"",0}, {"",0},
#line 23 "logtags.gperf"
      {"ftp.debug", 17},
#line 45 "logtags.gperf"
      {"ldap.debug", 39},
      {"",0},
#line 83 "logtags.gperf"
      {"radius.error", 77},
#line 84 "logtags.gperf"
      {"radius.policy", 78},
#line 85 "logtags.gperf"
      {"radius.request", 79},
      {"",0}, {"",0},
#line 82 "logtags.gperf"
      {"radius.debug", 76},
      {"",0}, {"",0},
#line 69 "logtags.gperf"
      {"plug.debug", 63},
#line 28 "logtags.gperf"
      {"ftp.session", 22},
      {"",0},
#line 149 "logtags.gperf"
      {"x11.violation", 143},
      {"",0},
#line 7 "logtags.gperf"
      {"core.accounting", 1},
      {"",0}, {"",0}, {"",0},
#line 86 "logtags.gperf"
      {"radius.session", 80},
      {"",0},
#line 87 "logtags.gperf"
      {"radius.violation", 81},
      {"",0}, {"",0}, {"",0},
#line 25 "logtags.gperf"
      {"ftp.policy", 19},
      {"",0}, {"",0}, {"",0},
#line 32 "logtags.gperf"
      {"http.info", 26},
      {"",0}, {"",0}, {"",0}, {"",0}, {"",0}, {"",0}, {"",0},
      {"",0}, {"",0},
#line 8 "logtags.gperf"
      {"core.auth", 2},
#line 31 "logtags.gperf"
      {"http.debug", 25},
      {"",0}, {"",0}, {"",0}, {"",0}, {"",0}, {"",0}, {"",0},
      {"",0},
#line 53 "logtags.gperf"
      {"lp.policy", 47},
      {"",0}, {"",0}, {"",0}, {"",0}, {"",0}, {"",0}, {"",0},
      {"",0}, {"",0}, {"",0}, {"",0}, {"",0}, {"",0}, {"",0},
      {"",0}, {"",0},
#line 99 "logtags.gperf"
      {"satyr.error", 93},
      {"",0},
#line 29 "logtags.gperf"
      {"ftp.violation", 23},
      {"",0}, {"",0}, {"",0}, {"",0}, {"",0}, {"",0}, {"",0},
      {"",0}, {"",0}, {"",0}, {"",0},
#line 30 "logtags.gperf"
      {"http.accounting", 24},
      {"",0}, {"",0}, {"",0}, {"",0}, {"",0}, {"",0}, {"",0},
      {"",0}, {"",0}, {"",0}, {"",0}, {"",0}, {"",0}, {"",0},
      {"",0}, {"",0}, {"",0}, {"",0}, {"",0}, {"",0}, {"",0},
      {"",0}, {"",0}, {"",0}, {"",0}, {"",0}, {"",0}, {"",0},
      {"",0}, {"",0}, {"",0}, {"",0}, {"",0}, {"",0}, {"",0},
      {"",0}, {"",0}, {"",0}, {"",0}, {"",0}, {"",0}, {"",0},
      {"",0}, {"",0}, {"",0}, {"",0}, {"",0}, {"",0}, {"",0},
      {"",0}, {"",0}, {"",0}, {"",0}, {"",0}, {"",0}, {"",0},
      {"",0},
#line 51 "logtags.gperf"
      {"lp.debug", 45}
    };

  if (len <= MAX_WORD_LENGTH && len >= MIN_WORD_LENGTH)
    {
      unsigned int key = hash (str, len);

      if (key <= MAX_HASH_VALUE)
        {
          const char *s = wordlist[key].name;

          if (*str == *s && !strcmp (str + 1, s + 1))
            return &wordlist[key];
        }
    }
  return 0;
}
