/****************************
   Supports parsing rules for QX, Surge, and Clash
   Applicable apps: Surge, Shadowrocket, Stash, Loon
***************************/
const script_start = Date.now();
const JS_NAME = 'Script Hub: Rule Set Conversion';
const $ = new Env(JS_NAME);

let arg;
if (typeof $argument != 'undefined') {
  arg = Object.fromEntries($argument.split('&').map(item => item.split('=')));
} else {
  arg = {};
}

// Timeout setting (same as script-converter.js)
const HTTP_TIMEOUT = ($.getval('Parser_http_timeout') ?? 20) * 1000;

// Target app
const isEgern = 'object' == typeof egern;
const isLanceX = 'undefined' != typeof $native;
if (isLanceX || isEgern) {
  $environment = { language: 'zh-Hans', system: 'iOS', 'surge-build': '2806', 'surge-version': '5.20.0' };
}

const url = $request.url;
let req = url.split(/file\/_start_\//)[1].split(/\/_end_\//)[0];
let reqArr = req.match('%F0%9F%98%82') ? req.split('%F0%9F%98%82') : [req];
// $.log("Original link：" + req);
let urlArg = url.split(/\/_end_\//)[1];

let resFile = urlArg.split('?')[0];
let resFileName = resFile.substring(0, resFile.lastIndexOf('.'));

// Identify app by User-Agent in request headers
const appUa = $request.headers['user-agent'] || $request.headers['User-Agent'];

// Get parameters
const queryObject = parseQueryString(urlArg);
// $.log("Parameters:" + $.toStr(queryObject));

// Target type
const isSurgetarget = queryObject.target == 'surge-rule-set';
const isStashtarget = queryObject.target == 'stash-rule-set';
const isLoontarget = queryObject.target == 'loon-rule-set';
const isRockettarget = queryObject.target == 'shadowrocket-rule-set';
const isSurgedomainset = queryObject.target == 'surge-domain-set';
const isSurgedomainset2 = queryObject.target == 'surge-domain-set2';
const isStashdomainset = queryObject.target == 'stash-domain-set';
const isStashdomainset2 = queryObject.target == 'stash-domain-set2';

let localText = queryObject.localtext != undefined ? '\n' + queryObject.localtext : ''; // Plain text input

let noNtf = queryObject.noNtf ? istrue(queryObject.noNtf) : false; // Default to notifications enabled

let localsetNtf = $.lodash_get(arg, 'Notify') || $.getval('ScriptHub Notification') || '';

noNtf = localsetNtf == 'Enable notifications' ? false : localsetNtf == 'Disable notifications' ? true : noNtf;

let bodyBox = [];

if (queryObject.target == 'rule-set') {
  if (appUa.search(/Surge|LanceX|Egern|Stash|Loon|Shadowrocket/i) != -1) {
    isSurgeiOS = appUa.search(/Surge|LanceX|Egern/i) != -1;
    isStashiOS = appUa.search(/Stash/i) != -1;
    isLooniOS = appUa.search(/Loon/i) != -1;
    isShadowrocket = appUa.search(/Shadowrocket/i) != -1;
  } else {
    isSurgeiOS = $.isSurge();
    isStashiOS = $.isStash();
    isLooniOS = $.isLoon();
    isShadowrocket = $.isShadowrocket();
  }
} else {
  isSurgeiOS = isSurgetarget;
  isStashiOS = isStashtarget;
  isLooniOS = isLoontarget;
  isShadowrocket = isRockettarget;
}

let Rin0 = queryObject.y != undefined ? getArgArr(queryObject.y) : null;
let Rout0 = queryObject.x != undefined ? getArgArr(queryObject.x) : null;
let ipNoResolve = istrue(queryObject.nore);
let sni = queryObject.sni != undefined ? getArgArr(queryObject.sni) : null;

let evJsori = queryObject.evalScriptori;
let evJsmodi = queryObject.evalScriptmodi;
let evUrlori = queryObject.evalUrlori;
let evUrlmodi = queryObject.evalUrlmodi;

// Custom request headers
const reqHeaders = { headers: {} };

if (queryObject.headers) {
  decodeURIComponent(queryObject.headers)
    .split(/\r?\n/)
    .map(i => {
      if (/.+:.+/.test(i)) {
        const [_, key, value] = i.match(/^(.*?):(.*)$/);
        if (key?.length > 0 && value?.length > 0) {
          reqHeaders.headers[key] = value;
        }
      }
    });
}

let other = []; // Unsupported rules
let ruleSet = []; // Parsed rules
let domainSet = []; // Domain set
let outRules = []; // Excluded rules

let noResolve; // IP rules do not resolve domain names
let ruleType; // Rule type
let ruleValue; // Rule value

!(async () => {
  if (evUrlori) {
    evUrlori = (await $.http.get(evUrlori)).body;
  }
  if (evUrlmodi) {
    evUrlmodi = (await $.http.get(evUrlmodi)).body;
  }

  if (req == 'http://local.text') {
    body = localText;
  } else {
    for (let i = 0; i < reqArr.length; i++) {
      let res = await http(reqArr[i], reqHeaders);
      let reStatus = res.status;
      body = reStatus == 200 ? res.body : reStatus == 404 ? '#!error=404: Not Found' : '';
      reStatus == 404 && $.msg(JS_NAME, 'Source link is invalid', '404: Not Found ---> ' + reqArr[i], '');

      if (body.match(/^(?:\s)*\/\*[\s\S]*?(?:\r|\n)\s*\*+\//)) {
        body = body.match(/^(?:\n|\r)*\/\*([\s\S]*?)(?:\r|\n)\s*\*+\//)[1];
        bodyBox.push(body);
      } else {
        bodyBox.push(body);
      }
    } // for
    body = bodyBox.join('\n\n') + localText;
  }

  eval(evJsori);
  eval(evUrlori);

  body = body.match(/[^\r\n]+/g);

  for await (let [y, x] of body.entries()) {
    x = x
      .replace(/^payload:/, '')
      .replace(/^ *(#|;|\/\/)/, '#')
      .replace(/^ *- */, '')
      .replace(/(^[^#].+)\x20+\/\/.+/, '$1')
      .replace(/(\{[0-9]+)\,([0-9]*\})/g, '$1t&zd;$2')
      .replace(/(^[^U].*(\[|=|{|\\|\/.*\.js).*)/i, '')
      .replace(/'|"/g, '')
      .replace(/^(\.|\*|\+)\.?/, 'DOMAIN-SUFFIX,')
      .replace(/^\[.*|^\s*$/,'');

    if (!x.match(/^ *#/) && !x.match(/,/) && x != '') {
      if (x.search(/[0-9]\/[0-9]/) != -1) {
        x = 'IP-CIDR,' + x;
      } else if (x.search(/([0-9]|[a-z]):([0-9]|[a-z])/) != -1) {
        x = 'IP-CIDR6,' + x;
      } else {
        x = 'DOMAIN,' + x;
      }
    }
    // Remove comments
    if (Rin0 != null) {
      for (let i = 0; i < Rin0.length; i++) {
        const elem = Rin0[i];
        if (x.indexOf(elem) != -1) {
          x = x.replace(/^#/, '');
        }
      } // loop end
    } // Remove comments end

    // Add comments
    if (Rout0 != null) {
      for (let i = 0; i < Rout0.length; i++) {
        const elem = Rout0[i];
        if (x.indexOf(elem) != -1) {
          x = x.replace(/(.+)/, ';#$1');
        }
      } // loop end
    } // Add comments end

    // IP rules do not resolve domain names
    if (ipNoResolve === true) {
      if (x.match(/^ip6?-[ca]/i) != null) {
        x = x + ',no-resolve';
      } else {
      }
    } else {
    } // Add no-resolve to IP rules end

    // SNI sniffing
    if (sni != null) {
      for (let i = 0; i < sni.length; i++) {
        const elem = sni[i];
        if (x.indexOf(elem) != -1) {
          x = x.replace(/^([^,]*),/, '$1,*');
        }
      } // loop end
    } // Add SNI sniffing end

    if (isSurgeiOS || isLooniOS) {
      if (x.match(/^IP-CIDR/g) != null) {
        x = x.replace(/^IP-CIDR/, 'IP-CIDR,');
      } else {
        if (x.match(/(domain|ip|gfwlist)/) != null) {
          x = x.replace(/^DOMAIN/, 'DOMAIN,');
        }
      }
    }
    if (isStashiOS || isShadowrocket) {
      if (x.match(/^IP-CIDR/g) != null) {
        x = x.replace(/^IP-CIDR/, 'IP-CIDR6,');
      }
    }

    if (isSurgetarget) {
      ruleSet.push(x);
    } else if (isStashtarget) {
      domainSet.push(x);
    } else if (isLoontarget) {
      ruleSet.push(x);
    } else if (isRockettarget) {
      ruleSet.push(x);
    } else if (isSurgedomainset) {
      ruleSet.push(x);
    } else if (isSurgedomainset2) {
      ruleSet.push(x);
    } else if (isStashdomainset) {
      domainSet.push(x);
    } else if (isStashdomainset2) {
      domainSet.push(x);
    } else {
      other.push(x);
    }
  } // loop end

  if (ruleSet.length > 0) {
    if (isSurgeiOS) {
      ruleSet = 'Surge Rule:\n' + ruleSet.join('\n');
    } else if (isStashiOS) {
      ruleSet = 'Stash Rule:\n' + ruleSet.join('\n');
    } else if (isLooniOS) {
      ruleSet = 'Loon Rule:\n' + ruleSet.join('\n');
    } else if (isShadowrocket) {
      ruleSet = 'Shadowrocket Rule:\n' + ruleSet.join('\n');
    }
  }

  if (domainSet.length > 0) {
    if (isSurgeiOS) {
      domainSet = 'Surge Domain name Rule:\n' + domainSet.join('\n');
    } else if (isStashiOS) {
      domainSet = 'Stash Domain name Rule:\n' + domainSet.join('\n');
    } else if (isLooniOS) {
      domainSet = 'Loon Domain name Rule:\n' + domainSet.join('\n');
    } else if (isShadowrocket) {
      domainSet = 'Shadowrocket Domain name Rule:\n' + domainSet.join('\n');
    }
  }

  if (ruleSet.length > 0) {
    $.msg(JS_NAME, 'Conversion Successful', ruleSet.join('\n'), '');
  }

  if (domainSet.length > 0) {
    $.msg(JS_NAME, 'Domain Set Conversion Successful', domainSet.join('\n'), '');
  }

  if (other.length > 0) {
    $.msg(JS_NAME, 'Unsupported Rules Detected', other.join('\n'), '');
  }

  let runTime = ((Date.now() - script_start) / 1000).toFixed(2);
  $.log('Execution Time: ' + runTime + 's');
})().catch(e => $.logErr(e));

function istrue(str) {
  if (str == 'true' || str == '1') {
    return true;
  } else if (str == 'false' || str == '0') {
    return false;
  } else {
    return str;
  }
}

function getArgArr(str) {
  return str.split('+').map(i => i.replace(/%20/g, ' ').replace(/%2C/g, ',').replace(/%2F/g, '/').replace(/%2B/g, '+'));
}

function parseQueryString(url) {
  let query = {};
  if (url) {
    url.replace(/([?&])([^=]+)=([^&]*)/g, (match, separator, key, value) => {
      query[key] = decodeURIComponent(value);
    });
  }
  return query;
}

async function http(url, opts) {
  let timeout = opts.timeout || HTTP_TIMEOUT;
  try {
    const response = await $.http.get(url, { timeout });
    return response;
  } catch (error) {
    return { status: error.status, body: '' };
  }
}
