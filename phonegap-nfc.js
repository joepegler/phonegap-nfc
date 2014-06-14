var Cription = (function Cription() {
    var _privateVars = {
        aes : { 
            AES_Sbox : new Array(
                99,124,119,123,242,107,111,197,48,1,103,43,254,215,171,
                118,202,130,201,125,250,89,71,240,173,212,162,175,156,164,114,192,183,253,
                147,38,54,63,247,204,52,165,229,241,113,216,49,21,4,199,35,195,24,150,5,154,
                7,18,128,226,235,39,178,117,9,131,44,26,27,110,90,160,82,59,214,179,41,227,
                47,132,83,209,0,237,32,252,177,91,106,203,190,57,74,76,88,207,208,239,170,
                251,67,77,51,133,69,249,2,127,80,60,159,168,81,163,64,143,146,157,56,245,
                188,182,218,33,16,255,243,210,205,12,19,236,95,151,68,23,196,167,126,61,
                100,93,25,115,96,129,79,220,34,42,144,136,70,238,184,20,222,94,11,219,224,
                50,58,10,73,6,36,92,194,211,172,98,145,149,228,121,231,200,55,109,141,213,
                78,169,108,86,244,234,101,122,174,8,186,120,37,46,28,166,180,198,232,221,
                116,31,75,189,139,138,112,62,181,102,72,3,246,14,97,53,87,185,134,193,29,
                158,225,248,152,17,105,217,142,148,155,30,135,233,206,85,40,223,140,161,
                137,13,191,230,66,104,65,153,45,15,176,84,187,22
            ),
            AES_ShiftRowTab : new Array(0,5,10,15,4,9,14,3,8,13,2,7,12,1,6,11),
            AES_Init:function () {
                this.AES_Sbox_Inv = new Array(256);
                for(var i = 0; i < 256; i++){
                    this.AES_Sbox_Inv[this.AES_Sbox[i]] = i;
                }
                this.AES_ShiftRowTab_Inv = new Array(16);
                for(var i = 0; i < 16; i++){
                    this.AES_ShiftRowTab_Inv[this.AES_ShiftRowTab[i]] = i;
                }
                this.AES_xtime = new Array(256);
                for(var i = 0; i < 128; i++) {
                    this.AES_xtime[i] = i << 1;
                    this.AES_xtime[128 + i] = (i << 1) ^ 0x1b;
                }
            },
            AES_Done:function () {
                delete this.AES_Sbox_Inv;
                delete this.AES_ShiftRowTab_Inv;
                delete this.AES_xtime;
            }, 
            AES_ExpandKey:function (key) {
                var kl = key.length, ks, Rcon = 1;
                switch (kl) {
                    case 16: 
                        ks = 16 * (10 + 1); 
                    break;
                    case 24: 
                        ks = 16 * (12 + 1); 
                    break;
                    case 32: 
                        ks = 16 * (14 + 1); 
                    break;
                    default: 
                        console.log("AES_ExpandKey: Only key lengths of 16, 24 or 32 bytes allowed!");
                }
                for(var i = kl; i < ks; i += 4) {
                    var temp = key.slice(i - 4, i);
                    if (i % kl == 0) {
                        temp = new Array(this.AES_Sbox[temp[1]] ^ Rcon, this.AES_Sbox[temp[2]], this.AES_Sbox[temp[3]], this.AES_Sbox[temp[0]]); 
                        if ((Rcon <<= 1) >= 256){
                            Rcon ^= 0x11b;
                        }
                    }
                    else if ((kl > 24) && (i % kl == 16)){
                        temp = new Array(this.AES_Sbox[temp[0]], this.AES_Sbox[temp[1]], this.AES_Sbox[temp[2]], this.AES_Sbox[temp[3]]);
                    }
                    for(var j = 0; j < 4; j++){
                        key[i + j] = key[i + j - kl] ^ temp[j];
                    }
                }
            },
            AES_Encrypt:function (block, key) {
                var l = key.length;
                this.AES_AddRoundKey(block, key.slice(0, 16));
                for(var i = 16; i < l - 16; i += 16) {
                    this.AES_SubBytes(block, this.AES_Sbox);
                    this.AES_ShiftRows(block,this.AES_ShiftRowTab);
                    this.AES_MixColumns(block);
                    this.AES_AddRoundKey(block, key.slice(i, i + 16));
                }
                this.AES_SubBytes(block, this.AES_Sbox);
                this.AES_ShiftRows(block, this.AES_ShiftRowTab);
                this.AES_AddRoundKey(block, key.slice(i, l));
            },
            AES_Decrypt : function (block, key) {
                var l = key.length;
                this.AES_AddRoundKey(block, key.slice(l - 16, l));
                this.AES_ShiftRows(block, this.AES_ShiftRowTab_Inv);
                this.AES_SubBytes(block, this.AES_Sbox_Inv);
                for(var i = l - 32; i >= 16; i -= 16) {
                    this.AES_AddRoundKey(block, key.slice(i, i + 16));
                    this.AES_MixColumns_Inv(block);
                    this.AES_ShiftRows(block, this.AES_ShiftRowTab_Inv);
                    this.AES_SubBytes(block, this.AES_Sbox_Inv);
                }
                this.AES_AddRoundKey(block, key.slice(0, 16));
            },
            AES_SubBytes : function (state, sbox) {
                for(var i = 0; i < 16; i++){
                    state[i] = sbox[state[i]];  
                }
            },
            AES_AddRoundKey : function (state, rkey) {
                for(var i = 0; i < 16; i++){
                    state[i] ^= rkey[i];
                }
            }, 
            AES_ShiftRows : function (state, shifttab) {
                var h = new Array().concat(state);
                for(var i = 0; i < 16; i++){
                    state[i] = h[shifttab[i]];
                }
            },
            AES_MixColumns : function (state) {
                for(var i = 0; i < 16; i += 4) {
                    var s0 = state[i + 0], s1 = state[i + 1];
                    var s2 = state[i + 2], s3 = state[i + 3];
                    var h = s0 ^ s1 ^ s2 ^ s3;
                    state[i + 0] ^= h ^ this.AES_xtime[s0 ^ s1];
                    state[i + 1] ^= h ^ this.AES_xtime[s1 ^ s2];
                    state[i + 2] ^= h ^ this.AES_xtime[s2 ^ s3];
                    state[i + 3] ^= h ^ this.AES_xtime[s3 ^ s0];
                }
            },
            AES_MixColumns_Inv : function (state) {
                for(var i = 0; i < 16; i += 4) {
                    var s0 = state[i + 0], s1 = state[i + 1];
                    var s2 = state[i + 2], s3 = state[i + 3];
                    var h = s0 ^ s1 ^ s2 ^ s3;
                    var xh = this.AES_xtime[h];
                    var h1 = this.AES_xtime[this.AES_xtime[xh ^ s0 ^ s2]] ^ h;
                    var h2 = this.AES_xtime[this.AES_xtime[xh ^ s1 ^ s3]] ^ h;
                    state[i + 0] ^= h1 ^ this.AES_xtime[s0 ^ s1];
                    state[i + 1] ^= h2 ^ this.AES_xtime[s1 ^ s2];
                    state[i + 2] ^= h1 ^ this.AES_xtime[s2 ^ s3];
                    state[i + 3] ^= h2 ^ this.AES_xtime[s3 ^ s0];
                }
            }
        },
        validate : {
            err :   "",
            isNotEmpty : function (value){
                if(typeof value === 'undefined'||value==""){
                    err+='\nA value you have entered is empty: '+value;
                    return false;
                }
                else{
                    return true;
                }
            },
            isValidKeyLength : function (value){
                if(value.length==16||value.length==24||value.length==32){
                    return true;
                }
                err+="\nInvalid key length: "+value.length+": "+value;
                return false;
            },
            isAlphaNumeric : function (value){
                if( /^[a-z0-9]+$/i.test(value)){
                    return true;
                }
                err+="\nInvalid key, not alphanumeric: "+value;
                return false;
            },
            isValid : function (test,data){
                err="***INVALID DATA***";
                var valid = false;
                switch(test){
                    case "secret":
                        if (_privateVars.validate.isNotEmpty(data)){
                            valid=true;
                        }
                    break;
                    case "key":
                        if (_privateVars.validate.isNotEmpty(data) && _privateVars.validate.isValidKeyLength(data) && _privateVars.validate.isAlphaNumeric(data)){
                            valid=true;
                        }
                    break;
                }
                if (!valid){
                    return false;
                }
                else{
                    return true;
                }
            }
        },
    };
    return function CriptionConstructor() {
        var _this = this; //Cache the `this` keyword
        _this.encrypt = function(options){
            if(!_privateVars.validate.isValid("key",options.key)){//If there is no key
                if(_privateVars.validate.isValid("key",localStorage.getItem('key'))){//if there is a valid key in storage
                    options.key=localStorage.getItem('key');//set the key to localStorage key
                }
            }
            if(options.store && _privateVars.validate.isValid("key",options.key)&& _privateVars.validate.isValid("key",localStorage.getItem('key'))){//If you want to store it and you have a valid key and localStorage.key isnt already set...
                localStorage.setItem('key', options.key);//set localStorage.key to the key you have 
            }    
            if(_privateVars.validate.isValid("secret",options.secret) && _privateVars.validate.isValid("key",options.key)){//if you have a valid secret and key then encrypt...
                //options.secret=util.stringToBytes(options.secret);//DELETE THIS IF WE WE ALREADY HAVE BYTES...                
                options.key=util.stringToBytes(options.key);//change the key to bytes
                _privateVars.aes.AES_Init();//start
                _privateVars.aes.AES_ExpandKey(options.key);//expand the key 
                _privateVars.aes.AES_Encrypt(options.secret, options.key);//encrypt
                _privateVars.aes.AES_Done();//finish
                return options.secret; //should be a byte array
            }
        };
        _this.decrypt=function(options){
            if(!options.key||options.key==""||options.key==='undefined'){//If no key was provided
                if( _privateVars.validate.isValid("key",localStorage.getItem('key')) ){//if there is a valid key in storage
                    options.key = localStorage.getItem('key');//set the key to the one in storage
                }
            }
            if(_privateVars.validate.isValid("secret",options.secret) && _privateVars.validate.isValid("key",options.key)){
                options.key=util.stringToBytes(options.key);
                _privateVars.aes.AES_Init();//start
                _privateVars.aes.AES_ExpandKey(options.key);//expand the key
                _privateVars.aes.AES_Decrypt(options.secret, options.key);//decrypt
                _privateVars.aes.AES_Done();//finish
                return options.secret;//should be a byte array
            }
        };
    };
}());
var cription = new Cription();


/*jshint  bitwise: false, camelcase: false, quotemark: false, unused: vars */
/*global cordova, console */
"use strict";

function handleNfcFromIntentFilter() {

    // This was historically done in cordova.addConstructor but broke with PhoneGap-2.2.0.
    // We need to handle NFC from an Intent that launched the application, but *after*
    // the code in the application's deviceready has run.  After upgrading to 2.2.0,
    // addConstructor was finishing *before* deviceReady was complete and the
    // ndef listeners had not been registered.
    // It seems like there should be a better solution.
    if (cordova.platformId === "android") {
        setTimeout(
            function () {
                cordova.exec(
                    function () {
                        console.log("Initialized the NfcPlugin");
                    },
                    function (reason) {
                        console.log("Failed to initialize the NfcPlugin " + reason);
                    },
                    "NfcPlugin", "init", []
                );
            }, 10
        );
    }
}

document.addEventListener('deviceready', handleNfcFromIntentFilter, false);

var ndef = {

    // see android.nfc.NdefRecord for documentation about constants
    // http://developer.android.com/reference/android/nfc/NdefRecord.html
    TNF_EMPTY: 0x0,
    TNF_WELL_KNOWN: 0x01,
    TNF_MIME_MEDIA: 0x02,
    TNF_ABSOLUTE_URI: 0x03,
    TNF_EXTERNAL_TYPE: 0x04,
    TNF_UNKNOWN: 0x05,
    TNF_UNCHANGED: 0x06,
    TNF_RESERVED: 0x07,

    RTD_TEXT: [0x54], // "T"
    RTD_URI: [0x55], // "U"
    RTD_SMART_POSTER: [0x53, 0x70], // "Sp"
    RTD_ALTERNATIVE_CARRIER: [0x61, 0x63], // "ac"
    RTD_HANDOVER_CARRIER: [0x48, 0x63], // "Hc"
    RTD_HANDOVER_REQUEST: [0x48, 0x72], // "Hr"
    RTD_HANDOVER_SELECT: [0x48, 0x73], // "Hs"

    /**
     * Creates a JSON representation of a NDEF Record.
     *
     * @tnf 3-bit TNF (Type Name Format) - use one of the TNF_* constants
     * @type byte array, containing zero to 255 bytes, must not be null
     * @id byte array, containing zero to 255 bytes, must not be null
     * @payload byte array, containing zero to (2 ** 32 - 1) bytes, must not be null
     *
     * @returns JSON representation of a NDEF record
     *
     * @see Ndef.textRecord, Ndef.uriRecord and Ndef.mimeMediaRecord for examples
     */
    record: function (tnf, type, id, payload) {

        // handle null values
        if (!tnf) { tnf = ndef.TNF_EMPTY; }
        if (!type) { type = []; }
        if (!id) { id = []; }
        if (!payload) { payload = []; }

        // convert strings to arrays
        if (!(type instanceof Array)) {
            type = nfc.stringToBytes(type);
        }
        if (!(id instanceof Array)) {
            id = nfc.stringToBytes(id);
        }
        if (!(payload instanceof Array)) {
            payload = nfc.stringToBytes(payload);
        }

        return {
            tnf: tnf,
            type: type,
            id: id,
            payload: payload
        };
    },

    /**
     * Helper that creates an NDEF record containing plain text.
     *
     * @text String of text to encode
     * @languageCode ISO/IANA language code. Examples: “fi”, “en-US”, “fr- CA”, “jp”. (optional)
     * @id byte[] (optional)
     */
    textRecord: function (text, languageCode, id) {
        var payload = textHelper.encodePayload(text, languageCode);
        if (!id) { id = []; }
        return ndef.record(ndef.TNF_WELL_KNOWN, ndef.RTD_TEXT, id, payload);
    },

    /**
     * Helper that creates a NDEF record containing a URI.
     *
     * @uri String
     * @id byte[] (optional)
     */
    uriRecord: function (uri, id) {
        var payload = uriHelper.encodePayload(uri);
        if (!id) { id = []; }
        return ndef.record(ndef.TNF_WELL_KNOWN, ndef.RTD_URI, id, payload);
    },

    /**
     * Helper that creates a NDEF record containing an absolute URI.
     *
     * An Absolute URI record means the URI describes the payload of the record.
     *
     * For example a SOAP message could use "http://schemas.xmlsoap.org/soap/envelope/"
     * as the type and XML content for the payload.
     *
     * Absolute URI can also be used to write LaunchApp records for Windows.
     *
     * See 2.4.2 Payload Type of the NDEF Specification
     * http://www.nfc-forum.org/specs/spec_list#ndefts
     *
     * Note that by default, Android will open the URI defined in the type
     * field of an Absolute URI record (TNF=3) and ignore the payload.
     * BlackBerry and Windows do not open the browser for TNF=3.
     *
     * To write a URI as the payload use ndef.uriRecord(uri)
     *
     * @uri String
     * @payload byte[] or String
     * @id byte[] (optional)
     */
    absoluteUriRecord: function (uri, payload, id) {
        if (!id) { id = []; }
        if (!payload) { payload = []; }
        return ndef.record(ndef.TNF_ABSOLUTE_URI, uri, id, payload);
    },

    /**
     * Helper that creates a NDEF record containing an mimeMediaRecord.
     *
     * @mimeType String
     * @payload byte[]
     * @id byte[] (optional)
     */
    mimeMediaRecord: function (mimeType, payload, id) {
        if (!id) { id = []; }
        return ndef.record(ndef.TNF_MIME_MEDIA, nfc.stringToBytes(mimeType), id, payload);
    },

    /**
     * Helper that creates an NDEF record containing an Smart Poster.
     *
     * @ndefRecords array of NDEF Records
     * @id byte[] (optional)
     */
    smartPoster: function (ndefRecords, id) {
        var payload = [];

        if (!id) { id = []; }

        if (ndefRecords)
        {
            // make sure we have an array of something like NDEF records before encoding
            if (ndefRecords[0] instanceof Object && ndefRecords[0].hasOwnProperty('tnf')) {
                payload = ndef.encodeMessage(ndefRecords);
            } else {
                // assume the caller has already encoded the NDEF records into a byte array
                payload = ndefRecords;
            }
        } else {
            console.log("WARNING: Expecting an array of NDEF records");
        }

        return ndef.record(ndef.TNF_WELL_KNOWN, ndef.RTD_SMART_POSTER, id, payload);
    },

    /**
     * Helper that creates an empty NDEF record.
     *
     */
    emptyRecord: function() {
        return ndef.record(ndef.TNF_EMPTY, [], [], []);
    },

    /**
     * Encodes an NDEF Message into bytes that can be written to a NFC tag.
     *
     * @ndefRecords an Array of NDEF Records
     *
     * @returns byte array
     *
     * @see NFC Data Exchange Format (NDEF) http://www.nfc-forum.org/specs/spec_list/
     */
    encodeMessage: function (ndefRecords) {

        var encoded = [],
            tnf_byte,
            type_length,
            payload_length,
            id_length,
            i,
            mb, me, // messageBegin, messageEnd
            cf = false, // chunkFlag TODO implement
            sr, // boolean shortRecord
            il; // boolean idLengthFieldIsPresent

        for(i = 0; i < ndefRecords.length; i++) {

            mb = (i === 0);
            me = (i === (ndefRecords.length - 1));
            sr = (ndefRecords[i].payload.length < 0xFF);
            il = (ndefRecords[i].id.length > 0);
            tnf_byte = ndef.encodeTnf(mb, me, cf, sr, il, ndefRecords[i].tnf);
            encoded.push(tnf_byte);

            type_length = ndefRecords[i].type.length;
            encoded.push(type_length);

            if (sr) {
                payload_length = ndefRecords[i].payload.length;
                encoded.push(payload_length);
            } else {
                payload_length = ndefRecords[i].payload.length;
                // 4 bytes
                encoded.push((payload_length >> 24));
                encoded.push((payload_length >> 16));
                encoded.push((payload_length >> 8));
                encoded.push((payload_length & 0xFF));
            }

            if (il) {
                id_length = ndefRecords[i].id.length;
                encoded.push(id_length);
            }

            encoded = encoded.concat(ndefRecords[i].type);

            if (il) {
                encoded = encoded.concat(ndefRecords[i].id);
            }

            encoded = encoded.concat(ndefRecords[i].payload);
        }

        return encoded;
    },

    /**
     * Decodes an array bytes into an NDEF Message
     *
     * @bytes an array bytes read from a NFC tag
     *
     * @returns array of NDEF Records
     *
     * @see NFC Data Exchange Format (NDEF) http://www.nfc-forum.org/specs/spec_list/
     */
    decodeMessage: function (bytes) {

        var bytes = bytes.slice(0), // clone since parsing is destructive
            ndef_message = [],
            tnf_byte,
            header,
            type_length = 0,
            payload_length = 0,
            id_length = 0,
            record_type = [],
            id = [],
            payload = [];

        while(bytes.length) {
            tnf_byte = bytes.shift();
            header = ndef.decodeTnf(tnf_byte);

            type_length = bytes.shift();

            if (header.sr) {
                payload_length = bytes.shift();
            } else {
                // next 4 bytes are length
                payload_length = ((0xFF & bytes.shift()) << 24) |
                    ((0xFF & bytes.shift()) << 26) |
                    ((0xFF & bytes.shift()) << 8) |
                    (0xFF & bytes.shift());
            }

            if (header.il) {
                id_length = bytes.shift();
            }

            record_type = bytes.splice(0, type_length);
            id = bytes.splice(0, id_length);
            payload = bytes.splice(0, payload_length);

            ndef_message.push(
                ndef.record(header.tnf, record_type, id, payload)
            );

            if (header.me) { break; } // last message
        }

        return ndef_message;
    },

    /**
     * Decode the bit flags from a TNF Byte.
     *
     * @returns object with decoded data
     *
     *  See NFC Data Exchange Format (NDEF) Specification Section 3.2 RecordLayout
     */
    decodeTnf: function (tnf_byte) {
        return {
            mb: (tnf_byte & 0x80) !== 0,
            me: (tnf_byte & 0x40) !== 0,
            cf: (tnf_byte & 0x20) !== 0,
            sr: (tnf_byte & 0x10) !== 0,
            il: (tnf_byte & 0x8) !== 0,
            tnf: (tnf_byte & 0x7)
        };
    },

    /**
     * Encode NDEF bit flags into a TNF Byte.
     *
     * @returns tnf byte
     *
     *  See NFC Data Exchange Format (NDEF) Specification Section 3.2 RecordLayout
     */
    encodeTnf: function (mb, me, cf, sr, il, tnf) {

        var value = tnf;

        if (mb) {
            value = value | 0x80;
        }

        if (me) {
            value = value | 0x40;
        }

        // note if cf: me, mb, li must be false and tnf must be 0x6
        if (cf) {
            value = value | 0x20;
        }

        if (sr) {
            value = value | 0x10;
        }

        if (il) {
            value = value | 0x8;
        }

        return value;
    }

};

// nfc provides javascript wrappers to the native phonegap implementation
var nfc = {

    addTagDiscoveredListener: function (callback, win, fail) {
        document.addEventListener("tag", callback, false);
        cordova.exec(win, fail, "NfcPlugin", "registerTag", []);
    },

    addMimeTypeListener: function (mimeType, callback, win, fail) {
        document.addEventListener("ndef-mime", callback, false);
        cordova.exec(win, fail, "NfcPlugin", "registerMimeType", [mimeType]);
    },

    addNdefListener: function (callback, win, fail) {
        document.addEventListener("ndef", callback, false);
        cordova.exec(win, fail, "NfcPlugin", "registerNdef", []);
    },

    addAesNdefListener: function (callback, win, fail, myKey) {
        function cb(nfcEvent){
            var ndefMessage = nfcEvent.tag.ndefMessage;
            for(i=0;i<ndefMessage.length;i++){
                for(j=0;j<ndefMessage[i].payload.length;j++){
                    if((ndefMessage[i].payload[j]<0)){
                        ndefMessage[i].payload[j] += 256;
                    }
                }
                cription.decrypt({secret:nfcEvent.tag.ndefMessage[i].payload, key:myKey});
                for(j=0;j<ndefMessage[i].payload.length;j++){
                    if(ndefMessage[i].payload[j]==0){
                        ndefMessage[i].payload.splice(j,16-j);
                    }
                }
            }
            callback(nfcEvent);
        };
        document.addEventListener("ndef", cb, false);
        cordova.exec(win, fail, "NfcPlugin", "registerNdef", []);
    },

    aesWrite: function (ndefMessage, win, fail, myKey) {
        for(i=0;i<ndefMessage.length;i++){
            for(j=ndefMessage[i].payload.length;j<16;j++){
                ndefMessage[i].payload.push(0);
            }
            var result = cription.encrypt({secret:ndefMessage[i].payload, key:myKey});                    
        }
        cordova.exec(win, fail, "NfcPlugin", "writeTag", [ndefMessage]);
    },

    addNdefFormatableListener: function (callback, win, fail) {
        document.addEventListener("ndef-formatable", callback, false);
        cordova.exec(win, fail, "NfcPlugin", "registerNdefFormatable", []);
    },

    write: function (ndefMessage, win, fail) {
        cordova.exec(win, fail, "NfcPlugin", "writeTag", [ndefMessage]);
    },

    share: function (ndefMessage, win, fail) {
        cordova.exec(win, fail, "NfcPlugin", "shareTag", [ndefMessage]);
    },

    unshare: function (win, fail) {
        cordova.exec(win, fail, "NfcPlugin", "unshareTag", []);
    },

    handover: function (uris, win, fail) {
        if (!Array.isArray(uris)) {
            uris = [ uris ];
        }
        cordova.exec(win, fail, "NfcPlugin", "handover", uris);
    },

    stopHandover: function (win, fail) {
        cordova.exec(win, fail, "NfcPlugin", "stopHandover", []);
    },

    erase: function (win, fail) {
        cordova.exec(win, fail, "NfcPlugin", "eraseTag", [[]]);
    },

    removeTagDiscoveredListener: function (callback, win, fail) {
        document.removeEventListener("tag", callback, false);
        cordova.exec(win, fail, "NfcPlugin", "removeTag", []);
    },

    removeMimeTypeListener: function(mimeType, callback, win, fail) {
        document.removeEventListener("ndef-mime", callback, false);
        cordova.exec(win, fail, "NfcPlugin", "removeMimeType", [mimeType]);
    },

    removeNdefListener: function (callback, win, fail) {
        document.removeEventListener("ndef", callback, false);
        cordova.exec(win, fail, "NfcPlugin", "removeNdef", []);
    }

};

var util = {
    // i must be <= 256
    toHex: function (i) {
        var hex;

        if (i < 0) {
            i += 256;
        }

        hex = i.toString(16);

        // zero padding
        if (hex.length === 1) {
            hex = "0" + hex;
        }

        return hex;
    },

    toPrintable: function(i) {

        if (i >= 0x20 & i <= 0x7F) {
            return String.fromCharCode(i);
        } else {
            return '.';
        }
    },

    bytesToString: function (bytes) {
        var bytesAsString = "";
        for (var i = 0; i < bytes.length; i++) {
            bytesAsString += String.fromCharCode(bytes[i]);
        }
        return bytesAsString;
    },

    // http://stackoverflow.com/questions/1240408/reading-bytes-from-a-javascript-string#1242596
    stringToBytes: function (str) {
        var ch, st, re = [];
        for (var i = 0; i < str.length; i++ ) {
            ch = str.charCodeAt(i);  // get char
            st = [];                 // set up "stack"
            do {
                st.push( ch & 0xFF );  // push byte to stack
                ch = ch >> 8;          // shift value down by 1 byte
            } while ( ch );
            // add stack contents to result
            // done because chars have "wrong" endianness
            re = re.concat( st.reverse() );
        }
        // return an array of bytes
        return re;
    },

    bytesToHexString: function (bytes) {
        var dec, hexstring, bytesAsHexString = "";
        for (var i = 0; i < bytes.length; i++) {
            if (bytes[i] >= 0) {
                dec = bytes[i];
            } else {
                dec = 256 + bytes[i];
            }
            hexstring = dec.toString(16);
            // zero padding
            if (hexstring.length === 1) {
                hexstring = "0" + hexstring;
            }
            bytesAsHexString += hexstring;
        }
        return bytesAsHexString;
    },
     
    // This function can be removed if record.type is changed to a String   
    /**
     * Returns true if the record's TNF and type matches the supplied TNF and type.
     *
     * @record NDEF record
     * @tnf 3-bit TNF (Type Name Format) - use one of the TNF_* constants
     * @type byte array or String
     */
    isType: function(record, tnf, type) {
        if (record.tnf === tnf) { // TNF is 3-bit
            var recordType;
            if (typeof(type) === 'string') {
                recordType = type;
            } else {
                recordType = nfc.bytesToString(type);
            }
            return (nfc.bytesToString(record.type) === recordType);
        }
        return false;
    }

};

// this is a module in ndef-js
var textHelper = {

    decodePayload: function (data) {

        var languageCodeLength = (data[0] & 0x1F), // 5 bits
            languageCode = data.slice(1, 1 + languageCodeLength),
            utf16 = (data[0] & 0x80) !== 0; // assuming UTF-16BE

        // TODO need to deal with UTF in the future
        // console.log("lang " + languageCode + (utf16 ? " utf16" : " utf8"));

        return util.bytesToString(data.slice(languageCodeLength + 1));
    },

    // encode text payload
    // @returns an array of bytes
    encodePayload: function(text, lang, encoding) {

        // ISO/IANA language code, but we're not enforcing
        if (!lang) { lang = 'en'; }

        var encoded = util.stringToBytes(lang + text);
        encoded.unshift(lang.length);

        return encoded;
    }

};

// this is a module in ndef-js
var uriHelper = {
    // URI identifier codes from URI Record Type Definition NFCForum-TS-RTD_URI_1.0 2006-07-24
    // index in array matches code in the spec
    protocols: [ "", "http://www.", "https://www.", "http://", "https://", "tel:", "mailto:", "ftp://anonymous:anonymous@", "ftp://ftp.", "ftps://", "sftp://", "smb://", "nfs://", "ftp://", "dav://", "news:", "telnet://", "imap:", "rtsp://", "urn:", "pop:", "sip:", "sips:", "tftp:", "btspp://", "btl2cap://", "btgoep://", "tcpobex://", "irdaobex://", "file://", "urn:epc:id:", "urn:epc:tag:", "urn:epc:pat:", "urn:epc:raw:", "urn:epc:", "urn:nfc:" ],

    // decode a URI payload bytes
    // @returns a string
    decodePayload: function (data) {
        var prefix = uriHelper.protocols[data[0]];
        if (!prefix) { // 36 to 255 should be ""
            prefix = "";
        }
        return prefix + util.bytesToString(data.slice(1));
    },

    // shorten a URI with standard prefix
    // @returns an array of bytes
    encodePayload: function (uri) {

        var prefix,
            protocolCode,
            encoded;

        // check each protocol, unless we've found a match
        // "urn:" is the one exception where we need to keep checking
        // slice so we don't check ""
        uriHelper.protocols.slice(1).forEach(function(protocol) {
            if ((!prefix || prefix === "urn:") && uri.indexOf(protocol) === 0) {
                prefix = protocol;
            }
        });

        if (!prefix) {
            prefix = "";
        }

        encoded = util.stringToBytes(uri.slice(prefix.length));
        protocolCode = uriHelper.protocols.indexOf(prefix);
        // prepend protocol code
        encoded.unshift(protocolCode);

        return encoded;
    }
};

// added since WP8 must call a named function
// TODO consider switching NFC events from JS events to using the PG callbacks
function fireNfcTagEvent(eventType, tagAsJson) {
    setTimeout(function () {
        var e = document.createEvent('Events');
        e.initEvent(eventType, true, false);
        e.tag = JSON.parse(tagAsJson);
        console.log(e.tag);
        document.dispatchEvent(e);
    }, 10);
}

// textHelper and uriHelper aren't exported, add a property
ndef.uriHelper = uriHelper;
ndef.textHelper = textHelper;

// create aliases
nfc.bytesToString = util.bytesToString;
nfc.stringToBytes = util.stringToBytes;
nfc.bytesToHexString = util.bytesToHexString;

// kludge some global variables for plugman js-module support
// eventually these should be replaced and referenced via the module
window.nfc = nfc;
window.ndef = ndef;
window.util = util;
window.fireNfcTagEvent = fireNfcTagEvent;
