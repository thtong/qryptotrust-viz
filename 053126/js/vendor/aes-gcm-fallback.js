
    // Pure-JS AES-256-GCM fallback using AES-CTR + manual GCM tag
    // Only used when crypto.subtle is unavailable (plain HTTP remote access)
    (function() {
        if (window._hasSubtle) {
            // Web Crypto available — no fallback needed, but define stubs
            window._aesGcmEncrypt = function() { throw new Error('Use crypto.subtle'); };
            window._aesGcmDecrypt = function() { throw new Error('Use crypto.subtle'); };
            return;
        }

        // Minimal AES-256-GCM using aes-js CTR mode + GHASH
        // If aes-js loaded from CDN, use it; otherwise use inline AES
        var hasAesJs = typeof aesjs !== 'undefined';

        function aesEncryptBlock(block, key) {
            if (hasAesJs) {
                var ecb = new aesjs.ModeOfOperation.ecb(key);
                return new Uint8Array(ecb.encrypt(block));
            }
            // Inline AES-256 single block encrypt (NIST FIPS 197)
            var SBOX=[99,124,119,123,242,107,111,197,48,1,103,43,254,215,171,118,202,130,201,125,250,89,71,240,173,212,162,175,156,164,114,192,183,253,147,38,54,63,247,204,52,165,229,241,113,216,49,21,4,199,35,195,24,150,5,154,7,18,128,226,235,39,178,117,9,131,44,26,27,110,90,160,82,59,214,179,41,227,47,132,83,209,0,237,32,252,177,91,106,203,190,57,74,76,88,207,208,239,170,251,67,77,51,133,69,249,2,127,80,60,159,168,81,163,64,143,146,157,56,245,188,182,218,33,16,255,243,210,205,12,19,236,95,151,68,23,196,167,126,61,100,93,25,115,96,129,79,220,34,42,144,136,70,238,184,20,222,94,11,219,224,50,58,10,73,6,36,92,194,211,172,98,145,149,228,121,231,200,55,109,141,213,78,169,108,86,244,234,101,122,174,8,186,120,37,46,28,166,180,198,232,221,116,31,75,189,139,138,112,62,181,102,72,3,246,14,97,53,87,185,134,193,29,158,225,248,152,17,105,217,142,148,155,30,135,233,206,85,40,223,140,161,137,13,191,230,66,104,65,153,45,15,176,84,187,22];
            var RCON=[1,2,4,8,16,32,64,128,27,54];
            var nk=8,nr=14,nb=4;
            var w=new Array(nb*(nr+1));
            for(var i=0;i<nk;i++) w[i]=(key[4*i]<<24)|(key[4*i+1]<<16)|(key[4*i+2]<<8)|key[4*i+3];
            for(var i=nk;i<w.length;i++){
                var t=w[i-1];
                if(i%nk===0){t=((t<<8)|(t>>>24))>>>0;t=(SBOX[(t>>>24)&255]<<24)|(SBOX[(t>>>16)&255]<<16)|(SBOX[(t>>>8)&255]<<8)|SBOX[t&255];t^=(RCON[i/nk-1]<<24);}
                else if(i%nk===4){t=(SBOX[(t>>>24)&255]<<24)|(SBOX[(t>>>16)&255]<<16)|(SBOX[(t>>>8)&255]<<8)|SBOX[t&255];}
                w[i]=(w[i-nk]^t)>>>0;
            }
            // State is column-major: state[row][col]
            var s=new Array(4);for(var r=0;r<4;r++){s[r]=new Array(4);for(var c=0;c<4;c++)s[r][c]=block[r+4*c];}
            // AddRoundKey 0
            for(var c=0;c<4;c++)for(var r=0;r<4;r++)s[r][c]^=(w[c]>>>(24-8*r))&255;
            for(var rnd=1;rnd<=nr;rnd++){
                // SubBytes
                for(var r=0;r<4;r++)for(var c=0;c<4;c++)s[r][c]=SBOX[s[r][c]];
                // ShiftRows
                var t1=s[1][0];s[1][0]=s[1][1];s[1][1]=s[1][2];s[1][2]=s[1][3];s[1][3]=t1;
                var t2=s[2][0],t3=s[2][1];s[2][0]=s[2][2];s[2][1]=s[2][3];s[2][2]=t2;s[2][3]=t3;
                var t4=s[3][3];s[3][3]=s[3][2];s[3][2]=s[3][1];s[3][1]=s[3][0];s[3][0]=t4;
                // MixColumns (skip last round)
                if(rnd<nr){
                    for(var c=0;c<4;c++){
                        var a=s[0][c],b=s[1][c],cc=s[2][c],d=s[3][c];
                        function x2(v){return((v<<1)^((v&128)?27:0))&255;}
                        s[0][c]=x2(a)^(x2(b)^b)^cc^d;
                        s[1][c]=a^x2(b)^(x2(cc)^cc)^d;
                        s[2][c]=a^b^x2(cc)^(x2(d)^d);
                        s[3][c]=(x2(a)^a)^b^cc^x2(d);
                    }
                }
                // AddRoundKey
                for(var c=0;c<4;c++)for(var r=0;r<4;r++)s[r][c]^=(w[rnd*nb+c]>>>(24-8*r))&255;
            }
            var out=new Uint8Array(16);
            for(var r=0;r<4;r++)for(var c=0;c<4;c++)out[r+4*c]=s[r][c];
            return out;
        }

        function incCtr(c){for(var i=15;i>=12;i--){c[i]=(c[i]+1)&255;if(c[i]!==0)break;}}

        function aesCtr(data,key,ctr){
            var out=new Uint8Array(data.length);var c=new Uint8Array(ctr);
            for(var i=0;i<data.length;i+=16){
                var blk=aesEncryptBlock(c,key);
                var len=Math.min(16,data.length-i);
                for(var j=0;j<len;j++)out[i+j]=data[i+j]^blk[j];
                incCtr(c);
            }
            return out;
        }

        function ghash(H,aad,ct){
            function gfMul(X,Y){
                var V=new Uint8Array(16);V.set(Y);var Z=new Uint8Array(16);
                for(var i=0;i<128;i++){
                    if((X[i>>>3]>>>(7-(i&7)))&1)for(var j=0;j<16;j++)Z[j]^=V[j];
                    var lsb=V[15]&1;
                    for(var j=15;j>0;j--)V[j]=(V[j]>>>1)|((V[j-1]&1)<<7);
                    V[0]>>>=1;if(lsb)V[0]^=0xe1;
                }
                return Z;
            }
            var X=new Uint8Array(16);
            // Process AAD (padded to 16)
            for(var i=0;i<aad.length;i+=16){var len=Math.min(16,aad.length-i);for(var j=0;j<len;j++)X[j]^=aad[i+j];X=gfMul(X,H);}
            // Process ciphertext (padded to 16)
            for(var i=0;i<ct.length;i+=16){var len=Math.min(16,ct.length-i);for(var j=0;j<len;j++)X[j]^=ct[i+j];X=gfMul(X,H);}
            // Length block: [aad_len_bits as 64-bit BE] || [ct_len_bits as 64-bit BE]
            var lb=new Uint8Array(16);
            var ab=aad.length*8,cb=ct.length*8;
            // Big-endian uint64: bytes 4-7 for aad bits (upper 32 bits are 0 for <512MB)
            lb[4]=(ab>>>24)&255;lb[5]=(ab>>>16)&255;lb[6]=(ab>>>8)&255;lb[7]=ab&255;
            // bytes 12-15 for ct bits
            lb[12]=(cb>>>24)&255;lb[13]=(cb>>>16)&255;lb[14]=(cb>>>8)&255;lb[15]=cb&255;
            for(var j=0;j<16;j++)X[j]^=lb[j];X=gfMul(X,H);
            return X;
        }

        window._aesGcmEncrypt=function(plaintext,key,iv){
            var J0=new Uint8Array(16);J0.set(iv);J0[15]=1;
            var ctr=new Uint8Array(J0);incCtr(ctr);
            var ct=aesCtr(plaintext,key,ctr);
            var H=aesEncryptBlock(new Uint8Array(16),key);
            var tag=ghash(H,new Uint8Array(0),ct);
            var eJ0=aesEncryptBlock(J0,key);
            for(var i=0;i<16;i++)tag[i]^=eJ0[i];
            var r=new Uint8Array(ct.length+16);r.set(ct);r.set(tag,ct.length);
            return r;
        };

        window._aesGcmDecrypt=function(ctTag,key,iv){
            if(ctTag.length<16)throw new Error('Ciphertext too short');
            var ct=ctTag.slice(0,-16);var rcv=ctTag.slice(-16);
            var J0=new Uint8Array(16);J0.set(iv);J0[15]=1;
            var H=aesEncryptBlock(new Uint8Array(16),key);
            var tag=ghash(H,new Uint8Array(0),ct);
            var eJ0=aesEncryptBlock(J0,key);
            for(var i=0;i<16;i++)tag[i]^=eJ0[i];
            var diff=0;for(var i=0;i<16;i++)diff|=tag[i]^rcv[i];
            if(diff!==0)throw new Error('AES-GCM authentication failed');
            var ctr=new Uint8Array(J0);incCtr(ctr);
            return aesCtr(ct,key,ctr);
        };

        console.log('[AES Fallback] Pure-JS AES-256-GCM loaded. crypto.subtle:', window._hasSubtle);
    })();
    