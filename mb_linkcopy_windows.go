package main

import (
	"runtime"
	"syscall"
	"unsafe"
)

// mbLinkCopyJS 注入到 Miniblink 每个 frame：右键 a 链接时把绝对地址复制到剪贴板。
// 不阻止默认右键菜单，保留浏览器原生的打开链接、复制文本等其他功能。
const mbLinkCopyJS = `(function(){
if(window.__ipscanLinkCopyReady) return;
window.__ipscanLinkCopyReady = true;
function copyText(text){
  try{
    if(navigator.clipboard && navigator.clipboard.writeText){
      navigator.clipboard.writeText(text);
      return;
    }
  }catch(_){}
  try{
    var ta = document.createElement('textarea');
    ta.value = text;
    ta.setAttribute('readonly', '');
    ta.style.position = 'fixed';
    ta.style.top = '-1000px';
    (document.body || document.documentElement).appendChild(ta);
    ta.select();
    document.execCommand('copy');
    ta.parentNode && ta.parentNode.removeChild(ta);
  }catch(_){}
}
function toast(text){
  var id = 'ipscan-link-copy-toast';
  var t = document.getElementById(id);
  if(!t){
    t = document.createElement('div');
    t.id = id;
    t.style.cssText = 'position:fixed;z-index:2147483647;left:50%;bottom:24px;transform:translateX(-50%);max-width:80vw;padding:8px 12px;border-radius:6px;background:rgba(17,24,39,.9);color:#fff;font:13px/1.5 sans-serif;box-shadow:0 4px 16px rgba(0,0,0,.25);pointer-events:none;word-break:break-all';
    (document.body || document.documentElement).appendChild(t);
  }
  t.textContent = '已复制链接地址：' + text;
  clearTimeout(window.__ipscanLinkCopyTimer);
  window.__ipscanLinkCopyTimer = setTimeout(function(){
    t.parentNode && t.parentNode.removeChild(t);
  }, 1800);
}
document.addEventListener('contextmenu', function(e){
  var node = e.target;
  while(node && node.nodeType !== 1) node = node.parentNode;
  while(node && node.parentElement){
    if(node.tagName === 'A' && node.getAttribute('href')) break;
    node = node.parentElement;
  }
  if(!node || node.tagName !== 'A') return;
  var href = node.href || node.getAttribute('href') || '';
  if(!href) return;
  copyText(href);
  toast(href);
}, true);
})();`

// registerMbLinkCopy 在 Blink 线程的 document-ready 回调里注入脚本，覆盖所有 frame（含跨域 iframe）。
func registerMbLinkCopy(proc func(string) *syscall.LazyProc, view uintptr) {
	docReady := proc("mbOnDocumentReadyInBlinkThread")
	runJS := proc("mbRunJsSync")
	if docReady.Find() != nil || runJS.Find() != nil {
		mbLogEvent("链接复制", "当前 mb132_x64.dll 不支持脚本注入，右键复制 a 链接地址不可用")
		return
	}
	cb := mbNewCallback(func(_ uintptr, _ unsafe.Pointer, frame uintptr) uintptr {
		script := append([]byte(mbLinkCopyJS), 0)
		runJS.Call(view, frame, uintptr(unsafe.Pointer(&script[0])), 0)
		runtime.KeepAlive(script)
		return 0
	})
	docReady.Call(view, cb, 0)
}
