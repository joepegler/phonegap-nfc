cordova-nfc-aes
===============

An adaptation of an NFC PhoneGap library (https://github.com/chariotsolutions/phonegap-nfc) with AES encryption included.
Two extra functions have been added:

nfc.addAesNdefListener
===============
Registers an event listener for any NDEF tag. For use when the ndefMessage on the tag has been encrypted using aesWrite.
```javascript
nfc.addNdefListener(callback, [onSuccess], [onFailure], [myKey]);
```
Parameters
```javascript
callback: The callback that is called when an NDEF tag is read.
onSuccess: (Optional) The callback that is called when the listener is added.
onFailure: (Optional) The callback that is called if there was an error.
myKey: (Optional) The encryption key used to decrypt the message.
```
Description
A ndef event is fired when a NDEF tag is read. ```localStorage('key') ``` is used to decrypt a message if 'myKey' is not set;
nfc.aesWrite
===============
Writes an encrypted NDEF Message to an NFC tag using encryption key. 
```javascript
var message = [
    ndef.textRecord("hello, world")
];
nfc.aesWrite(message, [onSuccess], [onFailure], [myKey]);
```

Parameters
```javascript
ndefMessage: An array of NDEF Records.
onSuccess: (Optional) The callback that is called when the tag is written.
onFailure: (Optional) The callback that is called if there was an error.
myKey: (Optional) The encryption key used to encrypt the message.
```
Description
Function nfc.aesWrite writes an encrypted NdefMessage to an NFC tag.
On Android this method must be called from within an NDEF Event Handler.
If an encryption key is not provided ```localStorage('key') ``` is used.
```localStorage('key') ``` is set when the user first uses a custom 'myKey'.

