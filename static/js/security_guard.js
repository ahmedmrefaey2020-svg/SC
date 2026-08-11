(function () {
    'use strict';

    const _k = [0x53, 0x65, 0x6e, 0x74, 0x69, 0x6e, 0x65, 0x6c, 0x53, 0x65, 0x63, 0x75, 0x72, 0x69, 0x74, 0x79];

    function _enc(str) {
        if (!str) return '';
        let res = '';
        for (let i = 0; i < str.length; i++) {
            res += String.fromCharCode(str.charCodeAt(i) ^ _k[i % _k.length]);
        }
        return btoa(res);
    }

    function _dec(b64) {
        if (!b64) return '';
        try {
            let str = atob(b64);
            let res = '';
            for (let i = 0; i < str.length; i++) {
                res += String.fromCharCode(str.charCodeAt(i) ^ _k[i % _k.length]);
            }
            return res;
        } catch (e) {
            return '';
        }
    }

    document.addEventListener('contextmenu', function (e) {
        e.preventDefault();
        return false;
    });

    document.addEventListener('keydown', function (e) {
        if (
            e.key === 'F12' ||
            (e.ctrlKey && e.shiftKey && (e.key === 'I' || e.key === 'i' || e.key === 'J' || e.key === 'j' || e.key === 'C' || e.key === 'c')) ||
            (e.ctrlKey && (e.key === 'U' || e.key === 'u' || e.key === 'S' || e.key === 's')) ||
            (e.metaKey && e.altKey && (e.key === 'I' || e.key === 'i' || e.key === 'U' || e.key === 'u'))
        ) {
            e.preventDefault();
            e.stopPropagation();
            return false;
        }
    });

    document.addEventListener('dragstart', function (e) {
        e.preventDefault();
    });

    document.addEventListener('selectstart', function (e) {
        if (e.target.tagName !== 'INPUT' && e.target.tagName !== 'TEXTAREA') {
            e.preventDefault();
        }
    });

    (function _dbgLoop() {
        let _threshold = 100;
        let _interval = setInterval(function () {
            let t0 = performance.now();
            (function () { })['constructor']('debugger')();
            let t1 = performance.now();
            if (t1 - t0 > _threshold) {
                clearInterval(_interval);
                document.body.innerHTML = '';
                window.location.href = '/';
            }
        }, 2000);
    })();

    (function _devtoolsSizeCheck() {
        let _w = window.outerWidth - window.innerWidth;
        let _h = window.outerHeight - window.innerHeight;
        if (_w > 160 || _h > 160) {
            window.location.href = '/';
        }
        window.addEventListener('resize', function () {
            let nw = window.outerWidth - window.innerWidth;
            let nh = window.outerHeight - window.innerHeight;
            if (nw > 160 || nh > 160) {
                window.location.href = '/';
            }
        });
    })();

    try {
        let _d = new Date();
        Object.defineProperty(_d, 'getFullYear', {
            get: function () {
                document.title = _enc(document.title || 'Sentinel IDS');
            }
        });
        console.log(_d);
        console.clear();
    } catch (_) {}

    window.SentinelSecurity = {
        encrypt: _enc,
        decrypt: _dec,
        protectHeaders: function (headers) {
            const h = headers || {};
            h['X-Sentinel-Protection'] = _enc('active-v2');
            return h;
        }
    };
})();
