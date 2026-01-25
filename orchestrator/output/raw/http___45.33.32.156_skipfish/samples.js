var mime_samples = [
  { 'mime': 'application/javascript', 'samples': [
    { 'url': 'http://45.33.32.156/shared/js/nst.js', 'dir': '_m0/0', 'linked': 2, 'len': 2235 } ]
  },
  { 'mime': 'application/xhtml+xml', 'samples': [
    { 'url': 'http://45.33.32.156/', 'dir': '_m1/0', 'linked': 2, 'len': 6974 },
    { 'url': 'http://45.33.32.156/icons/', 'dir': '_m1/1', 'linked': 2, 'len': 285 },
    { 'url': 'http://45.33.32.156/images/', 'dir': '_m1/2', 'linked': 2, 'len': 944 } ]
  },
  { 'mime': 'image/png', 'samples': [
    { 'url': 'http://45.33.32.156/shared/images/tiny-eyeicon.png', 'dir': '_m2/0', 'linked': 2, 'len': 529 } ]
  },
  { 'mime': 'image/svg+xml', 'samples': [
    { 'url': 'http://45.33.32.156/shared/images/nst-icons.svg', 'dir': '_m3/0', 'linked': 2, 'len': 4796 } ]
  },
  { 'mime': 'text/css', 'samples': [
    { 'url': 'http://45.33.32.156/shared/css/nst-foot.css', 'dir': '_m4/0', 'linked': 2, 'len': 582 },
    { 'url': 'http://45.33.32.156/shared/css/nst.css', 'dir': '_m4/1', 'linked': 2, 'len': 4658 },
    { 'url': 'http://45.33.32.156/site.css', 'dir': '_m4/2', 'linked': 2, 'len': 3926 } ]
  }
];

var issue_samples = [
  { 'severity': 2, 'type': 30601, 'samples': [
    { 'url': 'http://45.33.32.156/search/?q=1', 'extra': '', 'sid': '0', 'dir': '_i0/0' } ]
  },
  { 'severity': 1, 'type': 20101, 'samples': [
    { 'url': 'http://45.33.32.156/script.gif', 'extra': 'during path-based dictionary probes', 'sid': '0', 'dir': '_i1/0' },
    { 'url': 'http://45.33.32.156/shared/?_test1=c:\x5cwindows\x5csystem32\x5ccmd.exe&_test2=/etc/passwd&_test3=|/bin/sh&_test4=(SELECT%20*%20FROM%20nonexistent)%20--&_test5=\x3e/no/such/file&_test6=\x3cscript\x3ealert(1)\x3c/script\x3e&_test7=javascript:alert(1)', 'extra': 'IPS check', 'sid': '0', 'dir': '_i1/1' },
    { 'url': 'http://45.33.32.156/shared/css/?_test1=c:\x5cwindows\x5csystem32\x5ccmd.exe&_test2=/etc/passwd&_test3=|/bin/sh&_test4=(SELECT%20*%20FROM%20nonexistent)%20--&_test5=\x3e/no/such/file&_test6=\x3cscript\x3ealert(1)\x3c/script\x3e&_test7=javascript:alert(1)', 'extra': 'IPS check', 'sid': '0', 'dir': '_i1/2' },
    { 'url': 'http://45.33.32.156/shared/css/nst-foot.css?v=pre', 'extra': 'during parameter brute-force tests', 'sid': '0', 'dir': '_i1/3' },
    { 'url': 'http://45.33.32.156/shared/images/?_test1=c:\x5cwindows\x5csystem32\x5ccmd.exe&_test2=/etc/passwd&_test3=|/bin/sh&_test4=(SELECT%20*%20FROM%20nonexistent)%20--&_test5=\x3e/no/such/file&_test6=\x3cscript\x3ealert(1)\x3c/script\x3e&_test7=javascript:alert(1)', 'extra': 'IPS check', 'sid': '0', 'dir': '_i1/4' },
    { 'url': 'http://45.33.32.156/shared/js/?_test1=c:\x5cwindows\x5csystem32\x5ccmd.exe&_test2=/etc/passwd&_test3=|/bin/sh&_test4=(SELECT%20*%20FROM%20nonexistent)%20--&_test5=\x3e/no/such/file&_test6=\x3cscript\x3ealert(1)\x3c/script\x3e&_test7=javascript:alert(1)', 'extra': 'IPS check', 'sid': '0', 'dir': '_i1/5' } ]
  },
  { 'severity': 0, 'type': 10803, 'samples': [
    { 'url': 'http://45.33.32.156/', 'extra': '', 'sid': '0', 'dir': '_i2/0' },
    { 'url': 'http://45.33.32.156/shared/css/nst-foot.css', 'extra': '', 'sid': '0', 'dir': '_i2/1' },
    { 'url': 'http://45.33.32.156/shared/css/nst-foot.css?v=9876sfi', 'extra': '', 'sid': '0', 'dir': '_i2/2' },
    { 'url': 'http://45.33.32.156/shared/css/nst.css', 'extra': '', 'sid': '0', 'dir': '_i2/3' },
    { 'url': 'http://45.33.32.156/shared/css/nst.css?v=9876sfi', 'extra': '', 'sid': '0', 'dir': '_i2/4' },
    { 'url': 'http://45.33.32.156/shared/images/nst-icons.svg', 'extra': '', 'sid': '0', 'dir': '_i2/5' },
    { 'url': 'http://45.33.32.156/shared/js/nst.js', 'extra': '', 'sid': '0', 'dir': '_i2/6' },
    { 'url': 'http://45.33.32.156/shared/js/nst.js?v=9876sfi', 'extra': '', 'sid': '0', 'dir': '_i2/7' },
    { 'url': 'http://45.33.32.156/site.css', 'extra': '', 'sid': '0', 'dir': '_i2/8' } ]
  },
  { 'severity': 0, 'type': 10505, 'samples': [
    { 'url': 'http://45.33.32.156/', 'extra': 'q', 'sid': '0', 'dir': '_i3/0' } ]
  },
  { 'severity': 0, 'type': 10404, 'samples': [
    { 'url': 'http://45.33.32.156/images/', 'extra': 'Directory listing', 'sid': '0', 'dir': '_i4/0' } ]
  },
  { 'severity': 0, 'type': 10205, 'samples': [
    { 'url': 'http://45.33.32.156/sfi9876', 'extra': '', 'sid': '0', 'dir': '_i5/0' } ]
  },
  { 'severity': 0, 'type': 10202, 'samples': [
    { 'url': 'http://45.33.32.156/', 'extra': 'Apache/2.4.7 (Ubuntu)', 'sid': '0', 'dir': '_i6/0' } ]
  }
];

