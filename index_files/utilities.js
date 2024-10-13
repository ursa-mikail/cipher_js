
    //--------------------------- test -----------------------------//
    function bytes2hex(blk, dlm) {
        return Array.prototype.map.call(new Uint8Array(blk.buffer || blk),
        function (s) { return ('00' + s.toString(16)).slice(-2); }).join(dlm || '');
    }
    function toHexString(byteArray) {
        return Array.from(byteArray, function (byte) {
            return ('0' + (byte & 0xFF).toString(16)).slice(-2);
        }).join('')
    }
    function from_Hex(h) {

        h.replace(' ', '');
        var out = [], len = h.length, w = '';
        for (var i = 0; i < len; i += 2) {
            w = h[i];
            if (((i + 1) >= len) || typeof h[i + 1] === 'undefined') {
                w += '0';
            } else {
                w += h[i + 1];
            }
            out.push(parseInt(w, 16));
        }
        return out;
    }

    function bytesEqual(a, b) {
        var dif = 0;
        if (a.length !== b.length) return 0;
        for (var i = 0; i < a.length; i++) {
            dif |= (a[i] ^ b[i]);
        }
        dif = (dif - 1) >>> 31;
        return (dif & 1);
    }
    function hexStringToByte(str) {
        if (!str) {
            return new Uint8Array();
        }

        var a = [];
        for (var i = 0, len = str.length; i < len; i += 2) {
            a.push(parseInt(str.substr(i, 2), 16));
        }

        return new Uint8Array(a);
    }

    function ascii_to_hexa(str) {
        var arr1 = [];
        for (var n = 0, l = str.length; n < l; n++) {
            var hex = Number(str.charCodeAt(n)).toString(16);
            arr1.push(hex);
        }
        return arr1.join('');
    }

    function xor(a, b) {

        var res = []
        if (a.length > b.length) {
            for (var i = 0; i < b.length; i++) {
                res.push(a[i] ^ b[i])
            }
        } else {
            for (var i = 0; i < a.length; i++) {

                res.push(a[i] ^ b[i])
            }
        }
        return res;
    }
