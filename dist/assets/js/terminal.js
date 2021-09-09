'use strict';
// author: secoats
(function(){
const element_input = "pseudo-terminal-input";
const element_output = "pseudo-terminal-results";

const d = (new Date()).toString();
let banner = "Last Login: " + d;
banner += `
Welcome to OatOS release 0.1 (Cereal) Kernel 0.0.1-42

 ██████╗  █████╗ ████████╗     ██████╗ ███████╗
██╔═══██╗██╔══██╗╚══██╔══╝    ██╔═══██╗██╔════╝
██║   ██║███████║   ██║       ██║   ██║███████╗
██║   ██║██╔══██║   ██║       ██║   ██║╚════██║
╚██████╔╝██║  ██║   ██║       ╚██████╔╝███████║
 ╚═════╝ ╚═╝  ╚═╝   ╚═╝        ╚═════╝ ╚══════╝

OatOS comes with ABSOLUTELY NO WARRANTY, to the extend permitted by applicable law.

Welcome back 'guest'!

Type 'help' to see available commands.

`;

const helpMessage = `
  cat [file]             Print file content
  cd                     Change Directory
  clear                  Clear terminal content
  hash [input]           Create SHA256 hash of input (no spaces allowed)
  help                   Print this message
  id                     Print current user groups
  ls [-a]                List current directory content
  motd                   Print the welcome "message of the day" 
  pwd                    Print current/working directory
  whoami                 Print current user name
`;
//   su [user] [password]   Switch user
//   ls [-al]               List directory content

const about_secoats = `
This is a blog about computer networks, network security, security research and tools for pentesting.
`;

const answer = `
¯\\_(ツ)_/¯
`;

const secret = `
Just kidding, nothing to see here
`;

const root_flag = `
_    _.--.____.--._
( )=.-":;:;:;;':;:;:;"-._
 \\\\\\:;:;:;:;:;;:;::;:;:;:\\
  \\\\\\:;:;:;:;:;;:;:;:;:;:;\\
   \\\\\\:;:Congratulations!;:\\
    \\\\\\:;:;:;:;:;;:;::;:;:;:\\
     \\\\\\:;::;:;:;:;:;::;:;:;:\\
      \\\\\\;;:;:_:--:_:_:--:_;:;\\
       \\\\\\_.-"             "-._\\
        \\\\
         \\\\
          \\\\
           \\\\
            \\\\
             \\\\
`;

const about_oatos = `
This shell is pretending to be a *nix operating system. But it's really just some cheap JavaScript (sorry!).

I might add some flags to capture at some point (when I have too much time).
`;

class File {
    constructor(name, user, group, parent) {
        this.name = name;
        this.user = user;
        this.group = group;
        this.parent = parent;

        if(!!parent && parent instanceof Directory) {
            this.parent.addFile(this);
        }
    }
    getName() {
        return this.name;
    }
    getUser() {
        return this.user;
    }
    getGroup() {
        return this.group;
    }
    getPathString() {
        let result = this.name;
        result += "/";
        let next = this.parent;

        while(!!next) {
            result = next.name + "/" + result;
            next = next.parent;
        }
        return result;
    }
}

class ContentFile extends File {
    constructor(name, user, group, parent, content) {
        super(name, user, group, parent);
        this.content = content;
    }
    getContent() {
        return this.content;
    }
    setContent(content) {
        if(!!content) this.content = content;
    }
}

class Directory extends File {
    constructor(name, user, group, parent) {
        super(name, user, group, parent);
        this.children = new Map();
    }
    addFile(file) {
        if(file instanceof File)
            this.children.set(file.name, file);
    }
    getChildrenArray() {
        console.log(this.children);
        let items = Array.from(this.children.values());
        items.sort(function (a, b) {
            return a.getName().toLowerCase().localeCompare(b.getName().toLowerCase());
        });

        console.log(items);

        return items;
    }
}

const root_dir = new Directory("", "root", "root", null);
const home_dir = new Directory("home", "root", "root", root_dir);
const root_user_dir = new Directory("root", "root", "root", root_dir);
const var_dir = new Directory("var", "root", "root", root_dir);
const tmp_dir = new Directory("tmp", "root", "root", root_dir);
const guest_home_dir = new Directory("guest",'guest', 'guest', home_dir);

const secret_file = new ContentFile(".supersecret", 'guest', 'noob', guest_home_dir, secret);
const about_file = new ContentFile("about.txt", 'guest', 'guest', guest_home_dir, about_secoats);
const oatos_file = new ContentFile("oat_os.txt", 'guest', 'guest', guest_home_dir, about_oatos);
const root_flag_file = new ContentFile("flag.txt", 'root', 'noob', root_user_dir, root_flag);
const answer_file = new ContentFile("meaning_of_life.txt", 'root', 'noob', var_dir, answer);

document.addEventListener('DOMContentLoaded', function() {

    let current_working_dir = guest_home_dir;
    let user = "guest";
    let groups = ["guest", "noob"];

    document.getElementsByTagName('form')[0].onsubmit = function(evt) {
      evt.preventDefault();
      process();
    }

    const CMD_DICT = {
        'HELP': help,
        'Help': help,
        'help': help,
        'whoami': whoami,
        'id': id,
        'pwd': pwd,
        'clear': clear,
        'motd': motd,
        'hash': hash,
        'ls': listDir,
        'list': listDir,
        'cat': cat,
        'cd': changeDir
    };

    var process = function() {
        const inputText = document.getElementById(element_input).value.trim();
        
        // nothing to do
        if(!inputText) return;

        const args = inputText.split(" ");

        // nothing to do
        if(args.length < 1) return;

        const command = args[0];
        console.log("command", command);
        console.log(args);

        print("<p class='userEnteredText'>&#062 " + inputText + "</p>");
        runcmd(command, args);

        clearInput();
    }

    var runcmd = function(command, argu) {
        console.log("runcmd", command, argu);

        if(CMD_DICT.hasOwnProperty(command))
            CMD_DICT[command](argu);
        
        else
            print("<b>" + command + "</b>: command not found");
    }

    function whoami() {
        print(user);
    }

    function pwd() {
        print(current_working_dir.getPathString());
    }

    function help() {
        print(helpMessage);
    }

    function clear() {
        document.getElementById(element_output).innerHTML = '';
    }

    function id() {
        let res = [];
        for(let group of groups) {
            res.push( "(" + group +")" );
        }
        print(res.join());
    }

    function motd() {
        print(banner);
    }

    function hash(argu) {
        if(argu.length < 2) {
            print("Error: missing argument [input]");
            return;
        }
        let input = argu[1];
        let res = SHA256(input);
        print(res);
    }

    function listDir(argu) {
        let showall = false;

        if(argu.length > 1 && argu[1].startsWith("-")) {
            let dashparams = argu[1];
            if(dashparams.includes('a')) showall = true;
        }

        if(showall) {
            listDirFull(current_working_dir);
        }
        else {
            listDirSimple(current_working_dir);
        }
    }

    function listDirFull(dir) {
        const NL = "\n";
        // did not bother with permissions for now
        const dir_fake_permissions = 'drwxr-xr-x';
        const file_fake_permissions = '-rw-r--r--';
        let res = "";
        let last_len = 0;

        function combine(arr) {
            return arr.join(" ");
        }

        function pad(cont) {
            if(cont.length < last_len) {
                let padding = last_len - cont.length;
                return cont + ' '.repeat(padding);
            }
            else if(cont.length > last_len) {
                last_len = cont.length;
                return cont;
            }

            return cont;
        }

        res += dir.getPathString() + NL;
        res += pad( combine([ dir_fake_permissions, dir.getUser(), dir.getGroup()]) ) + '  <span class="console-dir">.</span>' + NL;

        if(!!dir.parent && dir.parent instanceof Directory) {
            res += pad( combine([ dir_fake_permissions, dir.parent.getUser(), dir.parent.getGroup()]) ) + '  <span class="console-dir">..</span>' + NL;
        }
        
        for(const child of dir.getChildrenArray()) {
            if(child instanceof ContentFile) {
                res += pad( combine([ file_fake_permissions, child.getUser(), child.getGroup()]) ) + '  <span class="highlight">' + child.getName() + '</span>' + NL;
            }
            else if(child instanceof Directory) {
                res += pad( combine([ dir_fake_permissions, child.getUser(), child.getGroup()]) ) + '  <span class="console-dir">' + child.getName() + '</span>' + NL;
            }
        }

        print(res);
    }

    function listDirSimple(dir) {
        const NL = "\n";
        let res = "";

        for(const child of dir.getChildrenArray()) {
            if(!child.getName().startsWith('.')) {
                if(child instanceof ContentFile) {         
                    res += '<span class="highlight">' + child.getName() + '</span>' + NL;
                }
    
                else if(child instanceof Directory) {
                    res += '<span class="console-dir">' + child.getName() + '</span>' + NL;
                }
            }
        }

        print(res);
    }

    function cat(argu) {
        if(argu.length < 2) {
            print("Error: missing argument [filename]");
            return;
        }

        let filename = argu[1];
        let found = null;

        for(let child of current_working_dir.getChildrenArray()) {
            if(child instanceof ContentFile && child.name == filename) {
                found = child;
                break;
            }
        }

        if(!!found) {
            print(found.getContent());
        } 
        else {
            print("File not found");
        }
    }

    function changeDir(argu) {
        if(argu.length < 2) {
            print("Error: missing argument [filename]");
            return;
        }

        let filename = argu[1];

        if(filename == '.') {
            changePwd(current_working_dir);
            return;
        }

        if(filename == '..') {
            if(current_working_dir.parent != null) {
                changePwd(current_working_dir.parent)
            }
            else {
                print("Directory not found");
            }

            return;
        }

        if(filename == '~') {
            changePwd(guest_home_dir);
            return;
        }

        let found = null;

        for(let child of current_working_dir.getChildrenArray()) {
            if(child instanceof Directory && child.name == filename) {
                found = child;
                break;
            }
        }

        if(!!found) {
            changePwd(found);
        } 
        else {
            print("Directory not found");
        }
    }

    function changePwd(dir) {
        current_working_dir = dir;
        print("Changed to: " + current_working_dir.getPathString());
    }

    //todo
    function getFile(path, session) {
        const parts = path.split("/");
        
        if(parts.length < 2 || parts[0] != this.root_dir.name) {
            throw new Error("FileSystem Error: Could not get non-root-based path");
        }

        let current = this.root_dir;
        

        for(let i = 1; i < parts.length; i++) {
            let next_name = parts[i];

            if(next_name == "") break;

            try {
                current = current.getChild(next_name);       
            } catch(err) {
                throw new Error(path + " does not exist");
            }

            if(!current.isReadable(session)) throw new Error(current.getPathString() + " is not readable by you");
        }

        return current;
    }
 
    var print = function(content){
        document.getElementById(element_output).innerHTML += "<pre>" + content + "</pre>";
        scrollBottom();
    }

    // Clear text input
    var clearInput = function(){
      document.getElementById(element_input).value = "";
    }
  
    // Scroll to the bottom of the results div
    var scrollBottom = function(){
      var terminalResultsDiv = document.getElementById(element_output);
      terminalResultsDiv.scrollTop = terminalResultsDiv.scrollHeight;
    }

    motd();

    // Get the focus to the text input to enter a word right away.
    document.getElementById(element_input).focus();
});

// webtoolkit.sha256.js
// Source: http://www.webtoolkit.info/javascript-sha256.html
// License: http://www.webtoolkit.info/license1/index.html
/**
*
*  Secure Hash Algorithm (SHA256)
*  http://www.webtoolkit.info/
*
*  Original code by Angel Marin, Paul Johnston.
*
**/
function SHA256(s){
 
	var chrsz   = 8;
	var hexcase = 0;
 
	function safe_add (x, y) {
		var lsw = (x & 0xFFFF) + (y & 0xFFFF);
		var msw = (x >> 16) + (y >> 16) + (lsw >> 16);
		return (msw << 16) | (lsw & 0xFFFF);
	}
 
	function S (X, n) { return ( X >>> n ) | (X << (32 - n)); }
	function R (X, n) { return ( X >>> n ); }
	function Ch(x, y, z) { return ((x & y) ^ ((~x) & z)); }
	function Maj(x, y, z) { return ((x & y) ^ (x & z) ^ (y & z)); }
	function Sigma0256(x) { return (S(x, 2) ^ S(x, 13) ^ S(x, 22)); }
	function Sigma1256(x) { return (S(x, 6) ^ S(x, 11) ^ S(x, 25)); }
	function Gamma0256(x) { return (S(x, 7) ^ S(x, 18) ^ R(x, 3)); }
	function Gamma1256(x) { return (S(x, 17) ^ S(x, 19) ^ R(x, 10)); }
 
	function core_sha256 (m, l) {
		var K = new Array(0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5, 0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3, 0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174, 0xE49B69C1, 0xEFBE4786, 0xFC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA, 0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147, 0x6CA6351, 0x14292967, 0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13, 0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85, 0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070, 0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3, 0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208, 0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2);
		var HASH = new Array(0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19);
		var W = new Array(64);
		var a, b, c, d, e, f, g, h, i, j;
		var T1, T2;
 
		m[l >> 5] |= 0x80 << (24 - l % 32);
		m[((l + 64 >> 9) << 4) + 15] = l;
 
		for ( var i = 0; i<m.length; i+=16 ) {
			a = HASH[0];
			b = HASH[1];
			c = HASH[2];
			d = HASH[3];
			e = HASH[4];
			f = HASH[5];
			g = HASH[6];
			h = HASH[7];
 
			for ( var j = 0; j<64; j++) {
				if (j < 16) W[j] = m[j + i];
				else W[j] = safe_add(safe_add(safe_add(Gamma1256(W[j - 2]), W[j - 7]), Gamma0256(W[j - 15])), W[j - 16]);
 
				T1 = safe_add(safe_add(safe_add(safe_add(h, Sigma1256(e)), Ch(e, f, g)), K[j]), W[j]);
				T2 = safe_add(Sigma0256(a), Maj(a, b, c));
 
				h = g;
				g = f;
				f = e;
				e = safe_add(d, T1);
				d = c;
				c = b;
				b = a;
				a = safe_add(T1, T2);
			}
 
			HASH[0] = safe_add(a, HASH[0]);
			HASH[1] = safe_add(b, HASH[1]);
			HASH[2] = safe_add(c, HASH[2]);
			HASH[3] = safe_add(d, HASH[3]);
			HASH[4] = safe_add(e, HASH[4]);
			HASH[5] = safe_add(f, HASH[5]);
			HASH[6] = safe_add(g, HASH[6]);
			HASH[7] = safe_add(h, HASH[7]);
		}
		return HASH;
	}
 
	function str2binb (str) {
		var bin = Array();
		var mask = (1 << chrsz) - 1;
		for(var i = 0; i < str.length * chrsz; i += chrsz) {
			bin[i>>5] |= (str.charCodeAt(i / chrsz) & mask) << (24 - i%32);
		}
		return bin;
	}
 
	function Utf8Encode(string) {
		string = string.replace(/\r\n/g,"\n");
		var utftext = "";
 
		for (var n = 0; n < string.length; n++) {
 
			var c = string.charCodeAt(n);
 
			if (c < 128) {
				utftext += String.fromCharCode(c);
			}
			else if((c > 127) && (c < 2048)) {
				utftext += String.fromCharCode((c >> 6) | 192);
				utftext += String.fromCharCode((c & 63) | 128);
			}
			else {
				utftext += String.fromCharCode((c >> 12) | 224);
				utftext += String.fromCharCode(((c >> 6) & 63) | 128);
				utftext += String.fromCharCode((c & 63) | 128);
			}
 
		}
 
		return utftext;
	}
 
	function binb2hex (binarray) {
		var hex_tab = hexcase ? "0123456789ABCDEF" : "0123456789abcdef";
		var str = "";
		for(var i = 0; i < binarray.length * 4; i++) {
			str += hex_tab.charAt((binarray[i>>2] >> ((3 - i%4)*8+4)) & 0xF) +
			hex_tab.charAt((binarray[i>>2] >> ((3 - i%4)*8  )) & 0xF);
		}
		return str;
	}
 
	s = Utf8Encode(s);
	return binb2hex(core_sha256(str2binb(s), s.length * chrsz));
}

})();