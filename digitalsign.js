document.addEventListener("DOMContentLoaded", function() {
    "use strict";

    if (window.crypto && !window.crypto.subtle && window.crypto.webkitSubtle) {
        window.crypto.subtle = window.crypto.webkitSubtle;
    }

    if (!window.crypto || !window.crypto.subtle) {
        alert("Your current browser does not support the Web Cryptography API! This page will not work.");
        return;
    }

    var keyPair;

    createAndSaveAKeyPair().
    then(function() {
        document.getElementById("sign").addEventListener("click", signTheFile);
        document.getElementById("verify").addEventListener("click", verifyTheFile);
    }).
    catch(function(err) {
        alert("Could not create a keyPair or enable buttons: " + err.message + "\n" + err.stack);
    });


    function createAndSaveAKeyPair() {
        return window.crypto.subtle.generateKey(
            {
                name: "RSASSA-PKCS1-v1_5",
                modulusLength: 2048,
                publicExponent: new Uint8Array([1, 0, 1]),
                hash: {name: "SHA-256"}
            },
            true,
            ["sign", "verify"]).
        then(function (key) {
            keyPair = key;
            return key;
        });
    }

    function signTheFile() {
        var sourceFile = document.getElementById("source-file").files[0];
        var reader = new FileReader();
        reader.onload = processTheFile;
        reader.readAsArrayBuffer(sourceFile);
        function processTheFile() {
            var reader = this;
            var plaintext = reader.result;
            sign(plaintext, keyPair.privateKey).
            then(function(blob) {
                var url = URL.createObjectURL(blob);
                document.getElementById("download-links").insertAdjacentHTML(
                    'beforeEnd',
                    '<li><a href="' + url + '">Signed file</a></li>');
            }).
            catch(function(err) {
                alert("Something went wrong signing: " + err.message + "\n" + err.stack);
            });
            function sign(plaintext, privateKey) {
                return window.crypto.subtle.sign(
                    {name: "RSASSA-PKCS1-v1_5"},
                    privateKey,
                    plaintext).
                then(packageResults);
                function packageResults(signature) {
                    var length = new Uint16Array([signature.byteLength]);
                    return new Blob(
                        [
                            length,
                            signature,
                            plaintext
                        ],
                        {type: "application/octet-stream"}
                    );
                }
            }
        }
    }

    function verifyTheFile() {
        var sourceFile = document.getElementById("source-file").files[0];
        var reader = new FileReader();
        reader.onload = processTheFile;
        reader.readAsArrayBuffer(sourceFile);
        function processTheFile() {
            var reader = this;
            var data = reader.result;
            var signatureLength = new Uint16Array(data, 0, 2)[0];
            var signature       = new Uint8Array( data, 2, signatureLength);
            var plaintext       = new Uint8Array( data, 2 + signatureLength);
            verify(plaintext, signature, keyPair.publicKey).
            then(function(blob) {
                if (blob === null) {
                    alert("Invalid signature!");
                } else {
                    alert("Signature is valid.");
                    var url = URL.createObjectURL(blob);
                    document.getElementById("download-links").insertAdjacentHTML(
                        'beforeEnd',
                        '<li><a href="' + url + '">Verified file</a></li>');
                }
            }).
            catch(function(err) {
                alert("Something went wrong verifying: " + err.message + "\n" + err.stack);
            });

            function verify(plaintext, signature, publicKey) {
                return window.crypto.subtle.verify(
                    {name: "RSASSA-PKCS1-v1_5"},
                    publicKey,
                    signature,
                    plaintext
                ).
                then(handleVerification);

                function handleVerification(successful) {
                    if (successful) {
                        return new Blob([plaintext], {type: "application/octet-stream"});
                    } else {
                        return null;
                    }
                }
            }
        }
    }
});